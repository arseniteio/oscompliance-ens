package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
)

func TestCheck(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"check", "testdata/web.yaml"}, &out); err != nil {
		t.Fatalf("check web.yaml: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "web (service)") || !strings.Contains(out.String(), "dmz (site)") {
		t.Fatalf("both documents should be read:\n%s", out.String())
	}

	out.Reset()
	if err := run([]string{"check", "testdata/bad.yaml"}, &out); err == nil {
		t.Fatal("bad.yaml should fail")
	}
	for _, want := range []string{"Bad_ID", "name is empty", "layer", "match is empty", "P-99"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	if err := run([]string{"check", "testdata/unknown-field.yaml"}, io.Discard); err == nil || !strings.Contains(err.Error(), "matches") {
		t.Fatalf("a misspelt field should be named, got %v", err)
	}

	if err := run([]string{"check", "testdata/web.yaml", "testdata/web.yaml"}, io.Discard); err == nil {
		t.Fatal("the same profile in two files should fail")
	}
}

func TestBuiltinsRoundTrip(t *testing.T) {
	for _, p := range catalog.BuiltinProfiles() {
		raw, err := encodeYAML([]catalog.Profile{p})
		if err != nil {
			t.Fatal(err)
		}
		back, err := decodeYAML(raw)
		if err != nil {
			t.Fatalf("%s: %v\n%s", p.ID, err, raw)
		}
		if d := profileDiff(normalizeProfile(p), back[0]); len(d) > 0 {
			t.Errorf("%s changed on the way through YAML: %v", p.ID, d)
		}
	}
}

func TestProfileDiff(t *testing.T) {
	old := catalog.Profile{ID: "web", Name: "Web", Layer: "service", Values: map[string]map[string]any{
		"op.acc.1": {"P-03": []any{"www-data"}, "P-10": float64(5)},
	}}
	updated := catalog.Profile{ID: "web", Name: "Web", Layer: "service", Values: map[string]map[string]any{
		"op.acc.1": {"P-03": []any{"www-data", "nginx"}, "P-10": 5, "P-11": []any{"x"}},
	}}
	got := strings.Join(profileDiff(old, updated), ", ")
	if got != "op.acc.1 P-03, op.acc.1 P-11 added" {
		t.Fatalf("diff: %s", got)
	}
}

func TestShortValue(t *testing.T) {
	cases := map[string]string{
		shortValue([]any{"a", "b"}, ""):           "a, b",
		shortValue([]any{"a", "b", "c", "d"}, ""): "a, b, c (+1 more)",
		shortValue("^svc-", "regex"):              "regex ^svc-",
		shortValue(float64(90), ""):               "90",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

type fakeIndexer struct {
	mu   sync.Mutex
	docs map[string]map[string]any
}

func (f *fakeIndexer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	switch {
	case strings.HasSuffix(r.URL.Path, "/_search"):
		var hits []map[string]any
		for _, d := range f.docs {
			hits = append(hits, map[string]any{"_source": d})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	case strings.HasSuffix(r.URL.Path, "/_refresh"):
		_, _ = io.WriteString(w, "{}")
	case r.Method == http.MethodPut:
		var d map[string]any
		_ = json.NewDecoder(r.Body).Decode(&d)
		f.docs[id] = d
		_, _ = io.WriteString(w, "{}")
	case r.Method == http.MethodDelete:
		if _, ok := f.docs[id]; !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"result":"not_found"}`)
			return
		}
		delete(f.docs, id)
		_, _ = io.WriteString(w, "{}")
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func TestPlanApplyExportDelete(t *testing.T) {
	fake := &fakeIndexer{docs: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	at := []string{"-indexer", srv.URL}

	var out bytes.Buffer
	if err := run(append([]string{"plan"}, append(at, "testdata/web.yaml")...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "new      web") || len(fake.docs) != 0 {
		t.Fatalf("plan should list new profiles and write nothing:\n%s", out.String())
	}

	if err := run(append([]string{"apply"}, append(at, "testdata/web.yaml")...), io.Discard); err != nil {
		t.Fatal(err)
	}
	doc := fake.docs["profile-web"]
	if doc["documentType"] != "PROFILE" || doc["configuration"].(map[string]any)["id"] != "web" {
		t.Fatalf("stored document: %v", doc)
	}

	out.Reset()
	if err := run(append([]string{"plan"}, append(at, "testdata/web.yaml")...), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "same     web") || !strings.Contains(out.String(), "same     dmz") {
		t.Fatalf("a second plan should find nothing to do:\n%s", out.String())
	}

	out.Reset()
	if err := run(append([]string{"export"}, append(at, "dmz")...), &out); err != nil {
		t.Fatal(err)
	}
	back, err := decodeYAML(out.Bytes())
	if err != nil || len(back) != 1 || back[0].ID != "dmz" || back[0].Replace["op.acc.1"][0] != "P-03" {
		t.Fatalf("export dmz: %v\n%s", err, out.String())
	}

	if err := run(append([]string{"delete"}, append(at, "dmz")...), io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, ok := fake.docs["profile-dmz"]; ok {
		t.Fatal("dmz should be gone")
	}
	if err := run(append([]string{"delete"}, append(at, "dmz")...), io.Discard); err == nil {
		t.Fatal("deleting a missing profile should fail")
	}
}

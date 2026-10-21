package opacc1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
)

const passwdFixture = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
toor:x:0:0:alt root:/root:/bin/sh
alice:x:1000:1000:Alice:/home/alice:/bin/bash
svc:x:1001:1001::/srv:/usr/sbin/nologin
bob:x:1002:1002::/home/bob:
broken line
neg:x:-1:0::/:/bin/sh
plus:x:+5:0::/:/bin/sh
:x:1003:1003::/:/bin/sh
`

// collect runs CollectEV01 over passwd content and returns the emitted facts.
func collect(t *testing.T, content string, uidMin int) []map[string]any {
	t.Helper()

	path := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return collectPath(t, path, uidMin)
}

func collectPath(t *testing.T, path string, uidMin int) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	e := emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")
	if err := CollectEV01(e, EV01Config{PasswdPath: path, UIDMin: uidMin}); err != nil {
		t.Fatal(err)
	}

	var facts []map[string]any
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		var f map[string]any
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		facts = append(facts, f)
	}
	return facts
}

func TestCollectEV01Read(t *testing.T) {
	facts := collect(t, passwdFixture, 1000)

	if len(facts) != 4 {
		t.Fatalf("want 3 records and 1 snapshot, got %d: %v", len(facts), facts)
	}

	wantRecords := []struct {
		user  string
		login bool
	}{{"alice", true}, {"svc", false}, {"bob", true}}
	for i, w := range wantRecords {
		f := facts[i]
		if f["fact"] != "account_record" || f["account_name"] != w.user || f["login_enabled"] != w.login {
			t.Errorf("record %d: got %v, want %s login=%v", i, f, w.user, w.login)
		}
	}

	s := facts[3]
	if s["fact"] != "account_inventory_snapshot" || s["source_status"] != "read" {
		t.Fatalf("last fact is not a read snapshot: %v", s)
	}
	if s["entries_total"] != float64(6) || s["records_emitted"] != float64(3) || s["uid_min"] != float64(1000) {
		t.Errorf("counts: %v", s)
	}
	if _, ok := s["source_error"]; ok {
		t.Errorf("source_error on a read snapshot: %v", s)
	}
	dups, _ := json.Marshal(s["duplicate_uids"])
	if string(dups) != `[{"account_names":["root","toor"],"uid":0}]` {
		t.Errorf("duplicate_uids: %s", dups)
	}
}

func TestCollectEV01NoDuplicatesIsEmptyArray(t *testing.T) {
	facts := collect(t, "root:x:0:0::/root:/bin/bash\n", 1000)

	if len(facts) != 1 {
		t.Fatalf("want only the snapshot, got %v", facts)
	}
	dups, ok := facts[0]["duplicate_uids"].([]any)
	if !ok || len(dups) != 0 || facts[0]["records_emitted"] != float64(0) {
		t.Errorf("want duplicate_uids [] and records_emitted 0, got %v", facts[0])
	}
}

func TestCollectEV01NotRead(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")

	cases := []struct {
		name   string
		facts  []map[string]any
		status string
	}{
		{"missing file", collectPath(t, missing, 1000), "unreadable"},
		{"directory", collectPath(t, t.TempDir(), 1000), "unreadable"},
		{"empty file", collect(t, "", 1000), "implausible"},
		{"no root", collect(t, "alice:x:1000:1000::/home/alice:/bin/bash\n", 1000), "implausible"},
	}
	for _, c := range cases {
		if len(c.facts) != 1 {
			t.Errorf("%s: want only the snapshot, got %v", c.name, c.facts)
			continue
		}
		s := c.facts[0]
		if s["source_status"] != c.status || s["source_error"] == "" || s["source_error"] == nil {
			t.Errorf("%s: got %v", c.name, s)
		}
		for _, k := range []string{"entries_total", "records_emitted", "duplicate_uids"} {
			if _, ok := s[k]; ok {
				t.Errorf("%s: %s present on a snapshot that was not read", c.name, k)
			}
		}
	}
}

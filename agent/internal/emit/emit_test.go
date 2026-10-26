package emit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

func TestEmitWritesFlatEnvelopeAndPayload(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "host-1", "0.1.0", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")
	e.now = func() time.Time { return time.Date(2026, 10, 21, 16, 0, 0, 0, time.FixedZone("CEST", 2*3600)) }

	rec := fact.GroupRecord{
		Envelope:  e.Envelope(fact.GroupRecordFact),
		GroupName: "sudo", GID: 27, Members: []string{"alice"},
	}
	if err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}

	if !bytes.HasSuffix(buf.Bytes(), []byte("}\n")) || bytes.Count(buf.Bytes(), []byte("\n")) != 1 {
		t.Fatalf("want one NDJSON line, got %q", buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"oscompliance": "1", "fact": "group_record", "ts": "2026-10-21T14:00:00Z",
		"host": "host-1", "agent_version": "0.1.0", "run_id": "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10",
		"group_name": "sudo", "gid": float64(27),
	}
	members, _ := got["members"].([]any)
	if len(members) != 1 || members[0] != "alice" {
		t.Errorf("members: %v", got["members"])
	}
	delete(got, "members")
	if len(got) != len(want) {
		t.Fatalf("fields: got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %v, want %v", k, got[k], v)
		}
	}
}

func TestNewRunIDIsUUIDv4(t *testing.T) {
	id, err := fact.NewRunID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '4' || !bytes.ContainsRune([]byte("89ab"), rune(id[19])) {
		t.Fatalf("not a UUID v4: %s", id)
	}
}

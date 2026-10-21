package emit

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fact"
)

func TestEmitWritesFlatEnvelopeAndPayload(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, "host-1", "0.1.0", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")
	e.now = func() time.Time { return time.Date(2026, 10, 21, 16, 0, 0, 0, time.FixedZone("CEST", 2*3600)) }

	rec := fact.AccountRecord{
		Envelope: e.Envelope(fact.AccountRecordFact),
		User:     "alice", UID: 1000, GID: 1000, Shell: "/bin/bash", LoginEnabled: true,
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
		"oscompliance": "1", "fact": "account_record", "ts": "2026-10-21T14:00:00Z",
		"host": "host-1", "agent_version": "0.1.0", "run_id": "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10",
		"user": "alice", "uid": float64(1000), "gid": float64(1000), "shell": "/bin/bash", "login_enabled": true,
	}
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

func TestSnapshotDuplicateUIDs(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		name string
		dups []fact.DuplicateUID
		want string
	}{
		{"read without duplicates", []fact.DuplicateUID{}, `"duplicate_uids":[]`},
		{"not read", nil, ""},
	} {
		var buf bytes.Buffer
		e := New(&buf, "h", "v", "r")
		s := fact.AccountInventorySnapshot{Envelope: e.Envelope(fact.AccountInventorySnapshotFact), EntriesTotal: &zero, DuplicateUIDs: tc.dups}
		if err := e.Emit(s); err != nil {
			t.Fatal(err)
		}
		has := bytes.Contains(buf.Bytes(), []byte(`"duplicate_uids"`))
		if (tc.want != "") != has || (tc.want != "" && !bytes.Contains(buf.Bytes(), []byte(tc.want))) {
			t.Errorf("%s: got %s", tc.name, buf.String())
		}
	}
}

package source

import (
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// Copied from an alert indexed in the lab (wazuh-alerts-*, rule 119001).
func TestDecodeIndexedFacts(t *testing.T) {
	record := map[string]any{
		"oscompliance": "1", "fact": "account_record", "ts": "2026-10-21T15:21:26Z",
		"host": "lab-agent-01", "agent_version": "9559fe8", "run_id": "0e037a39-0de3-4a5b-bb54-535dc8100cd7",
		"account_name": "jperez", "uid": "1001", "gid": "1001", "shell": "/bin/bash", "login_enabled": "true",
	}
	var r fact.AccountRecord
	if err := Decode(record, &r); err != nil {
		t.Fatal(err)
	}
	if r.AccountName != "jperez" || r.UID != 1001 || r.GID != 1001 || !r.LoginEnabled || r.RunID != "0e037a39-0de3-4a5b-bb54-535dc8100cd7" {
		t.Errorf("record: %+v", r)
	}

	snapshot := map[string]any{
		"oscompliance": "1", "fact": "account_inventory_snapshot", "run_id": "x",
		"source": "passwd", "source_path": "/etc/passwd", "source_status": "read",
		"uid_min": "1000", "entries_total": "23", "records_emitted": "4",
		"duplicate_uids": []any{map[string]any{"uid": float64(0), "account_names": []any{"root", "toor"}}},
	}
	var s fact.AccountInventorySnapshot
	if err := Decode(snapshot, &s); err != nil {
		t.Fatal(err)
	}
	if s.UIDMin != 1000 || s.EntriesTotal == nil || *s.EntriesTotal != 23 || s.RecordsEmitted == nil || *s.RecordsEmitted != 4 {
		t.Errorf("snapshot counts: %+v", s)
	}
	if len(s.DuplicateUIDs) != 1 || s.DuplicateUIDs[0].UID != 0 || len(s.DuplicateUIDs[0].AccountNames) != 2 {
		t.Errorf("duplicate_uids: %+v", s.DuplicateUIDs)
	}

	unread := map[string]any{"fact": "account_inventory_snapshot", "source_status": "unreadable", "source_error": "denied", "uid_min": "1000"}
	var u fact.AccountInventorySnapshot
	if err := Decode(unread, &u); err != nil {
		t.Fatal(err)
	}
	if u.EntriesTotal != nil || u.RecordsEmitted != nil || u.SourceError != "denied" {
		t.Errorf("unread snapshot: %+v", u)
	}
}

func TestDecodeRejectsBadScalars(t *testing.T) {
	var r fact.AccountRecord
	if err := Decode(map[string]any{"uid": "abc"}, &r); err == nil {
		t.Error("uid abc: want error")
	}
	if err := Decode(map[string]any{"login_enabled": "maybe"}, &r); err == nil {
		t.Error("login_enabled maybe: want error")
	}
}

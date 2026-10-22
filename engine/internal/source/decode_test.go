package source

import (
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// Copied from alerts indexed in the lab (wazuh-alerts-*, rule 119001).
func TestDecodeIndexedFacts(t *testing.T) {
	record := map[string]any{
		"oscompliance": "1", "fact": "identity_record", "ts": "2026-10-22T12:14:44Z",
		"host": "lab-agent-01", "agent_version": "0188f2b", "run_id": "fb98743f-321a-4045-8184-16216db37d03",
		"account_name": "jperez", "uid": "1001", "gid": "1001", "shell": "/bin/bash", "password_state": "locked",
		"authorized_keys": "1",
	}
	var r fact.IdentityRecord
	if err := Decode(record, &r); err != nil {
		t.Fatal(err)
	}
	if r.AccountName != "jperez" || r.UID != 1001 || r.GID != 1001 || r.AuthorizedKeys == nil || *r.AuthorizedKeys != 1 || r.RunID != "fb98743f-321a-4045-8184-16216db37d03" {
		t.Errorf("record: %+v", r)
	}

	snapshot := map[string]any{
		"oscompliance": "1", "fact": "identity_snapshot", "run_id": "x",
		"passwd_path": "/etc/passwd", "passwd_status": "read", "shadow_path": "/etc/shadow", "shadow_status": "read",
		"records_emitted": "25", "sshd_status": "read",
		"authorized_keys_files": []any{".ssh/authorized_keys", ".ssh/authorized_keys2"},
	}
	var s fact.IdentitySnapshot
	if err := Decode(snapshot, &s); err != nil {
		t.Fatal(err)
	}
	if s.RecordsEmitted == nil || *s.RecordsEmitted != 25 || len(s.AuthorizedKeysFiles) != 2 {
		t.Errorf("snapshot: %+v", s)
	}

	group := map[string]any{"fact": "group_record", "group_name": "sudo", "gid": "27", "members": []any{"ubuntu"}}
	var g fact.GroupRecord
	if err := Decode(group, &g); err != nil || g.GID != 27 || len(g.Members) != 1 {
		t.Errorf("group: %+v %v", g, err)
	}

	// No counter and keys unknown: the pointers stay nil.
	unread := map[string]any{"fact": "identity_record", "account_name": "kim", "uid": "1004"}
	var u fact.IdentityRecord
	if err := Decode(unread, &u); err != nil || u.AuthorizedKeys != nil {
		t.Errorf("unknown keys: %+v %v", u, err)
	}
}

func TestDecodeRejectsBadScalars(t *testing.T) {
	var r fact.IdentityRecord
	if err := Decode(map[string]any{"uid": "abc"}, &r); err == nil {
		t.Error("uid abc: want error")
	}
	if err := Decode(map[string]any{"authorized_keys": "many"}, &r); err == nil {
		t.Error("authorized_keys many: want error")
	}
}

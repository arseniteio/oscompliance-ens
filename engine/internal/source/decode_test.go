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

func TestAuthLines(t *testing.T) {

	m := accepted.FindStringSubmatch("2026-10-25T21:12:01+00:00 h sshd[1]: Accepted publickey for jperez from 10.0.0.9 port 4242 ssh2: ED25519-SK SHA256:abc")
	if m == nil || m[1] != "publickey" || m[2] != "ED25519-SK" {
		t.Errorf("publickey: %q", m)
	}

	m = accepted.FindStringSubmatch("h sshd[1]: Accepted keyboard-interactive/pam for ana from 10.0.0.9 port 1 ssh2")
	if m == nil || m[1] != "keyboard-interactive/pam" || m[2] != "" {
		t.Errorf("keyboard-interactive: %q", m)
	}

	for line, user := range map[string]string{
		"h sshd[1]: pam_faillock(sshd:auth): Consecutive login failures for user jperez account temporarily locked": "jperez",
		"h login[2]: pam_tally2(login:auth): user ana (1000) tally 6, deny 5":                                       "ana",
	} {
		m := lockoutLine.FindStringSubmatch(line)
		if m == nil || (m[1] != user && m[2] != user) {
			t.Errorf("%s: %q", line, m)
		}
	}
}

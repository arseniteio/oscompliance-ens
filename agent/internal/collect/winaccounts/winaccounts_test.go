package winaccounts

import (
	"errors"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

const localUsers = `{"source":"sam","users":[
{"name":"Administrator","sid":"S-1-5-21-1-2-3-500","enabled":true,"password_last_set":"2026-10-01T08:00:00.0000000Z","password_required":true,"must_change":false,"max_days":42,"expires":null,"last_logon":"2026-11-16T09:30:00.1234567Z"},
{"name":"Guest","sid":"S-1-5-21-1-2-3-501","enabled":false,"password_last_set":null,"password_required":false,"must_change":false,"max_days":null,"expires":null,"last_logon":null},
{"name":"ana","sid":"S-1-5-21-1-2-3-1001","enabled":true,"password_last_set":null,"password_required":false,"must_change":false,"max_days":null,"expires":"2027-01-31T23:00:00.0000000Z","last_logon":null}]}`

func TestIdentityMapsLocalAccounts(t *testing.T) {

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectIdentity(e, winps.Static(localUsers)) })
	if len(facts) != 4 {
		t.Fatalf("%d facts, want 3 records and a snapshot", len(facts))
	}

	admin, guest, ana, snapshot := facts[0], facts[1], facts[2], facts[3]
	for _, c := range []struct {
		got  any
		want any
	}{
		{admin["uid"], 500.0}, {admin["password_state"], "set"}, {admin["password_changed"], "2026-10-01"},
		{admin["password_max_days"], 42.0}, {admin["last_login"], "2026-11-16T09:30:00Z"}, {admin["shell"], ""},
		{guest["password_state"], "locked"}, {guest["authorized_keys"], 0.0},
		{ana["uid"], 1001.0}, {ana["password_state"], "empty"}, {ana["account_expires"], "2027-01-31"},
		{snapshot["fact"], "identity_snapshot"}, {snapshot["passwd_path"], "sam"}, {snapshot["records_emitted"], 3.0}, {snapshot["sshd_status"], "absent"},
	} {
		if c.got != c.want {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
	if _, ok := guest["password_max_days"]; ok {
		t.Error("an account whose password never expires has a maximum age")
	}
}

func TestIdentityReportsAFailedRead(t *testing.T) {
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectIdentity(e, winps.Failing(errors.New("access denied"))) })
	if len(facts) != 1 || facts[0]["passwd_status"] != "unreadable" || facts[0]["passwd_error"] != "access denied" {
		t.Fatalf("got %v", facts)
	}
}

func TestGroupsResolveMembers(t *testing.T) {

	out := `{"source":"sam","computer":"WS01","groups":[{"name":"Administrators","sid":"S-1-5-32-544","members":["WinNT://WORKGROUP/WS01/Administrator","WinNT://CORP/Domain Admins","WinNT://S-1-5-21-9-9-9-1105"]},{"name":"Guests","sid":"S-1-5-32-546","members":[]}]}`
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectGroups(e, winps.Static(out)) })

	if len(facts) != 3 || facts[0]["gid"] != 544.0 {
		t.Fatalf("got %v", facts)
	}
	members := facts[0]["members"].([]any)
	want := []string{"Administrator", `CORP\Domain Admins`, "S-1-5-21-9-9-9-1105"}
	for i, m := range want {
		if members[i] != m {
			t.Errorf("member %d = %v, want %s", i, members[i], m)
		}
	}
	if facts[1]["members"] == nil {
		t.Error("an empty group has no members list")
	}
}

func TestMember(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{"WinNT://CORP/WS01/svc", "svc"},
		{"WinNT://ws01/backup", "backup"},
		{"WinNT://NT AUTHORITY/INTERACTIVE", `NT AUTHORITY\INTERACTIVE`},
	} {
		if got := Member(c.path, "WS01"); got != c.want {
			t.Errorf("Member(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

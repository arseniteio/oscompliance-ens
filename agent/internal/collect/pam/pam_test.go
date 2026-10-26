package pam

import (
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func TestCollectPAM(t *testing.T) {

	dir := t.TempDir()

	// Debian style: @include.
	collecttest.Write(t, filepath.Join(dir, "sshd"), "# sshd\n@include common-auth\naccount required pam_nologin.so\n")
	collecttest.Write(t, filepath.Join(dir, "common-auth"), `auth	[success=1 default=ignore]	pam_unix.so nullok
auth requisite pam_deny.so # no fallback
auth required /lib/security/pam_faillock.so authfail \
	deny=3 unlock_time=0
`)

	// RHEL style: type include and substack, only that type is taken.
	collecttest.Write(t, filepath.Join(dir, "login"), "auth substack system-auth\npassword include system-auth\n")
	collecttest.Write(t, filepath.Join(dir, "system-auth"), "auth required pam_env.so\naccount required pam_unix.so\npassword requisite pam_pwquality.so minlen=12\n-session optional pam_systemd.so\n")

	// A loop and a missing include are problems, not failures.
	collecttest.Write(t, filepath.Join(dir, "su"), "@include su\n@include missing\n")

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Dir: dir, Services: []string{"sshd", "login", "su", "sudo"}})
	})

	var rules []map[string]any
	for _, f := range facts[:len(facts)-1] {
		rules = append(rules, f)
	}
	snapshot := facts[len(facts)-1]

	type rule struct{ service, kind, control, module string }
	want := []rule{
		{"sshd", "auth", "[success=1 default=ignore]", "pam_unix.so"},
		{"sshd", "auth", "requisite", "pam_deny.so"},
		{"sshd", "auth", "required", "pam_faillock.so"},
		{"sshd", "account", "required", "pam_nologin.so"},
		{"login", "auth", "required", "pam_env.so"},
		{"login", "password", "requisite", "pam_pwquality.so"},
	}

	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %v", len(rules), len(want), rules)
	}

	for i, w := range want {
		r := rules[i]
		if r["service"] != w.service || r["type"] != w.kind || r["control"] != w.control || r["module"] != w.module {
			t.Errorf("rule %d: got %v %v %v %v, want %v", i, r["service"], r["type"], r["control"], r["module"], w)
		}
	}

	// The continuation is joined and the include chain recorded.
	faillock := rules[2]
	if args := faillock["args"].([]any); len(args) != 2 || args[0] != "deny=3" {
		t.Errorf("faillock args: %v", faillock["args"])
	}
	if via := faillock["via"].([]any); len(via) != 1 || via[0] != filepath.Join(dir, "sshd") || faillock["line"] != 3.0 {
		t.Errorf("faillock via/line: %v %v", faillock["via"], faillock["line"])
	}
	if rules[1]["position"] != 1.0 || rules[4]["position"] != 0.0 {
		t.Errorf("positions: %v %v", rules[1]["position"], rules[4]["position"])
	}

	services := snapshot["services"].([]any)
	if len(services) != 3 || snapshot["records_emitted"] != 6.0 {
		t.Errorf("snapshot: %v", snapshot)
	}
	if problems := snapshot["problems"].([]any); len(problems) != 2 {
		t.Errorf("problems: %v", problems)
	}

	// Types keeps the stacks asked for, includes still followed.
	facts = collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Dir: dir, Services: []string{"sshd"}, Types: []string{"account"}})
	})
	if len(facts) != 2 || facts[0]["module"] != "pam_nologin.so" {
		t.Errorf("account only: %v", facts)
	}
}

func TestCollectPAMWithoutDir(t *testing.T) {

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Dir: filepath.Join(t.TempDir(), "pam.d"), Services: DefaultServices})
	})

	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("got %v", facts)
	}
}

package audit

import (
	"strings"
	"testing"
)

func TestParseWatches(t *testing.T) {

	got := parseWatches(`-w /srv/datos -p r -k oscompliance_read
-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S all -F dir=/srv/app -F perm=w -F key=oscompliance_write
`)
	if strings.Join(got, ",") != "/srv/datos oscompliance_read,/srv/app oscompliance_write" {
		t.Errorf("watches: %v", got)
	}

	if !auditRunning("enabled 1\nfailure 1\npid 812\n") || auditRunning("enabled 1\npid 0\n") || auditRunning("enabled 0\npid 9\n") {
		t.Error("auditctl -s reading")
	}
}

func TestAuditSafety(t *testing.T) {

	for p, ok := range map[string]bool{"/srv/datos": true, "/": false, "/etc": false, "relative": false, "/srv/../etc": false, "/srv/a b": false} {
		if (unsafeWatch(p) == "") != ok {
			t.Errorf("%q: %q", p, unsafeWatch(p))
		}
	}

	if n := len(permRules("amd64")); n != 10 {
		t.Errorf("amd64 rules: %d", n)
	}
	for _, r := range permRules("arm64") {
		for _, f := range r {
			if strings.Contains(f, "arch=b32") || strings.HasPrefix(f, "chmod") || strings.HasPrefix(f, "chown") {
				t.Errorf("arm64 rule %v", r)
			}
		}
	}
}

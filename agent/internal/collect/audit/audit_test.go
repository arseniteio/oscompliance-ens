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

func TestWatchRule(t *testing.T) {

	cases := []struct {
		watch watch
		dir   bool
		want  string
	}{
		{writeWatch, false, "-w /etc/ssh -p w -k oscompliance_write"},
		{attrWatch, true, "-w /etc/ssh -p a -k oscompliance_attr"},
		{readWatch, false, "-a always,exit -F path=/etc/ssh -F perm=r -F auid!=-1 -k oscompliance_read"},
		{readWatch, true, "-a always,exit -F dir=/etc/ssh -F perm=r -F auid!=-1 -k oscompliance_read"},
	}
	for _, c := range cases {
		if got := strings.Join(watchRule("/etc/ssh", c.watch, c.dir), " "); got != c.want {
			t.Errorf("%v dir=%v: %s", c.watch, c.dir, got)
		}
	}

	got := parseWatches("-a always,exit -S all -F dir=/srv/datos -F perm=r -F auid!=-1 -F key=oscompliance_read\n")
	if strings.Join(got, ",") != "/srv/datos oscompliance_read" {
		t.Errorf("a loaded read rule is recognised: %v", got)
	}
}

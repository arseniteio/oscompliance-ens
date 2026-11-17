package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
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

func TestHotReadPath(t *testing.T) {

	for path, hot := range map[string]string{
		"/etc/group":           "/etc/group",
		"/etc/ssl":             "/etc/ssl/certs",
		"/etc/ssl/certs/a.pem": "/etc/ssl/certs",
		"/usr/share/doc":       "/usr",
		"/etc/ssl/private":     "",
		"/etc/shadow":          "",
		"/etc/groups":          "",
		"/srv/datos":           "",
	} {
		if got := hotReadPath(path); got != hot {
			t.Errorf("%s: %q, want %q", path, got, hot)
		}
	}
}

func TestStaleRulesAreUnloaded(t *testing.T) {

	rules := parseRules(`-w /srv/old -p r -k oscompliance_read
-a always,exit -S all -F dir=/srv/keys -F perm=r -F auid!=-1 -F key=oscompliance_read
-a always,exit -S all -F dir=/srv/gone -F perm=r -F auid!=-1 -F key=oscompliance_read
-w /srv/keys -p w -k oscompliance_write
-w /etc/ssh -p w -k oscompliance_write
-w /usr/bin/sudo -p x -k oscompliance_exec
-w /srv/noisy -p w -k oscompliance_write
-a always,exit -S all -F path=/srv/noisy -F perm=r -F auid!=-1 -F key=oscompliance_read
`)
	paths := wazuh.SharedPaths{ReadWatches: []string{"/srv/keys", "/srv/old", "/srv/noisy"}, AuditWatches: []string{"/etc/ssh"}, ExecWatches: []string{"/usr/bin/sudo"}}
	suspended := Throttle{"/srv/noisy": time.Now().Add(time.Hour)}

	var got []string
	for _, r := range staleRules(rules, paths, suspended) {
		got = append(got, strings.Join(r.deletion(), " "))
	}
	want := []string{
		"-W /srv/old -p r -k oscompliance_read",
		"-d always,exit -F dir=/srv/gone -F perm=r -F auid!=-1 -k oscompliance_read",
		"-d always,exit -F path=/srv/noisy -F perm=r -F auid!=-1 -k oscompliance_read",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("stale rules:\n%s", strings.Join(got, "\n"))
	}
}

func TestCountReads(t *testing.T) {

	now := time.Unix(1731830000, 0)
	log := `type=SYSCALL msg=audit(1731829990.100:10): arch=c000003e syscall=257 success=yes key="oscompliance_read"
type=PATH msg=audit(1731829990.100:10): item=0 name="/srv/keys/" nametype=PARENT
type=PATH msg=audit(1731829990.100:10): item=1 name="/srv/keys/tls/server.key" nametype=NORMAL
type=SYSCALL msg=audit(1731829991.100:11): arch=c000003e syscall=257 success=yes key="oscompliance_read"
type=PATH msg=audit(1731829991.100:11): item=0 name=2F7372762F6B6579732F6120622E6B6579 nametype=NORMAL
type=SYSCALL msg=audit(1731829992.100:12): arch=c000003e syscall=257 success=yes key="identity"
type=PATH msg=audit(1731829992.100:12): item=0 name="/srv/keys/x" nametype=NORMAL
type=SYSCALL msg=audit(1731829000.100:13): arch=c000003e syscall=257 success=yes key="oscompliance_read"
type=PATH msg=audit(1731829000.100:13): item=0 name="/srv/keys/old" nametype=NORMAL
type=SYSCALL msg=audit(1731829993.100:14): arch=c000003e syscall=257 success=yes key="oscompliance_read"
type=PATH msg=audit(1731829993.100:14): item=0 name="/srv/keys/inner/k" nametype=NORMAL
type=SYSCALL msg=audit(1731829995.100:16): arch=c000003e syscall=257 success=yes key="oscompliance_read"
type=CWD msg=audit(1731829995.100:16): cwd="/srv/keys"
type=PATH msg=audit(1731829995.100:16): item=0 name="relative.key" nametype=NORMAL
type=SYSCALL msg=audit(1731829994.100:15): arch=c000003e syscall=257 success=no exit=-13 key="oscompliance_read"
type=PATH msg=audit(1731829994.100:15): item=0 name="/srv/keys/denied" nametype=NORMAL
`
	perPath, err := CountReads(strings.NewReader(log), []string{"/srv/keys", "/srv/keys/inner"}, now.Add(-5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if perPath["/srv/keys"] != 2 || perPath["/srv/keys/inner"] != 1 {
		t.Errorf("per path %v", perPath)
	}
}

func TestThrottleKeepsOnlyActiveSuspensions(t *testing.T) {

	path := filepath.Join(t.TempDir(), "audit-throttle.json")
	now := time.Now().Truncate(time.Second)
	if err := (Throttle{"/srv/a": now.Add(time.Hour), "/srv/b": now.Add(-time.Hour)}).Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadThrottle(path)
	if err != nil {
		t.Fatal(err)
	}
	active := got.Active(now)
	if _, ok := active["/srv/a"]; !ok || len(active) != 1 {
		t.Errorf("active: %v", active)
	}

	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadThrottle(path); err == nil || len(got) != 0 {
		t.Errorf("a broken file is reported and ignored: %v %v", got, err)
	}
	if got, err := LoadThrottle(filepath.Join(t.TempDir(), "none.json")); err != nil || len(got) != 0 {
		t.Errorf("no file is no suspension: %v %v", got, err)
	}
}

func TestGuardWithoutAuditdDoesNothing(t *testing.T) {
	dir := t.TempDir()
	suspended, err := Guard(GuardConfig{Auditctl: filepath.Join(dir, "auditctl"), Throttle: filepath.Join(dir, "throttle.json"), Limit: 60, Window: time.Minute}, time.Now())
	if err != nil || suspended != nil {
		t.Errorf("no auditctl: %v %v", suspended, err)
	}
}

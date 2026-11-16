package sudoers

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
)

func TestCollectSudoers(t *testing.T) {
	dir := t.TempDir()
	collecttest.WriteFile(t, filepath.Join(dir, "sudoers"), `Defaults env_reset
# a comment
User_Alias ADMINS = ana, %ops
Cmnd_Alias PKG = /usr/bin/apt
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
ADMINS ALL = PKG
#1005 ALL = /bin/true
jperez, \
  mgarcia ALL = NOPASSWD: /usr/bin/systemctl
!bob ALL = ALL
ALL ALL = /usr/bin/who
+devs ALL = ALL
@includedir `+filepath.Join(dir, "sudoers.d")+`
`, 0o440)
	collecttest.WriteFile(t, filepath.Join(dir, "sudoers.d/ops"), "%#1500 ALL = ALL\n", 0o440)
	collecttest.WriteFile(t, filepath.Join(dir, "sudoers.d/ops.dpkg-old"), "eve ALL = ALL\n", 0o440)
	collecttest.WriteFile(t, filepath.Join(dir, "sudoers.d/backup~"), "eve ALL = ALL\n", 0o440)

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Path: filepath.Join(dir, "sudoers")})
	})

	var grants []string
	for _, f := range facts[:len(facts)-1] {
		g := f["subject_kind"].(string) + ":" + f["subject"].(string)
		if f["nopasswd"] == true {
			g += "!"
		}
		grants = append(grants, g)
	}

	want := "user:root group:sudo user:ana group:ops uid:1005 user:jperez! user:mgarcia! gid:1500"
	if strings.Join(grants, " ") != want {
		t.Errorf("grants\n got %s\nwant %s", strings.Join(grants, " "), want)
	}

	s := facts[len(facts)-1]
	if s["status"] != "read" || s["blind_spots"] != float64(2) || s["records_emitted"] != float64(8) || len(s["files"].([]any)) != 2 {
		t.Errorf("snapshot: %v", s)
	}
	reasons, _ := json.Marshal(s["blind_spot_reasons"])
	if !strings.Contains(string(reasons), "ALL users granted") || !strings.Contains(string(reasons), "netgroup +devs") {
		t.Errorf("reasons: %s", reasons)
	}

	facts = collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Path: filepath.Join(dir, "nothing")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" || facts[0]["blind_spots"] != float64(0) {
		t.Errorf("absent: %v", facts)
	}
}

func TestSudoersReauthentication(t *testing.T) {
	dir := t.TempDir()
	collecttest.WriteFile(t, filepath.Join(dir, "sudoers"), `Defaults env_reset, timestamp_timeout=-1
Defaults:backup !authenticate
Defaults env_keep += "LANG, LC_ALL"
Cmnd_Alias SVC = /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
Cmnd_Alias NESTED = SVC, !/usr/bin/su
ana ALL = (root) NOPASSWD: /usr/bin/apt, PASSWD: /usr/bin/vi, /bin/ls
ops ALL = (ALL : ALL) CWD=/tmp NOPASSWD:SETENV: NESTED, ALL, !/usr/bin/passwd
bob ALL = NOPASSWD: UNDEFINED
eve ALL = /usr/bin/who, NOPASSWD: /usr/bin/x\, y
`, 0o440)

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Path: filepath.Join(dir, "sudoers")})
	})

	got := map[string]string{}
	specs := map[string]string{}
	for _, f := range facts[:len(facts)-1] {
		cmds, _ := json.Marshal(f["nopasswd_commands"])
		got[f["subject"].(string)] = string(cmds)
		specs[f["subject"].(string)], _ = f["spec"].(string)
	}
	if specs["ana"] != "ALL=(root) NOPASSWD: /usr/bin/apt, PASSWD: /usr/bin/vi, /bin/ls" {
		t.Errorf("spec: %q", specs["ana"])
	}

	want := map[string]string{
		"ana": `["/usr/bin/apt"]`,
		"ops": `["/usr/bin/systemctl restart nginx","/usr/bin/systemctl reload nginx","ALL"]`,
		"bob": `["UNDEFINED"]`,
		"eve": `["/usr/bin/x\\, y"]`,
	}
	for subject, cmds := range want {
		if got[subject] != cmds {
			t.Errorf("%s: got %s, want %s", subject, got[subject], cmds)
		}
	}

	var defaults []string
	for _, d := range facts[len(facts)-1]["defaults"].([]any) {
		m := d.(map[string]any)
		defaults = append(defaults, m["binding"].(string)+"|"+m["setting"].(string))
	}

	want2 := `|env_reset ; |timestamp_timeout=-1 ; :backup|!authenticate ; |env_keep += "LANG, LC_ALL"`
	if strings.Join(defaults, " ; ") != want2 {
		t.Errorf("defaults\n got %s\nwant %s", strings.Join(defaults, " ; "), want2)
	}
}

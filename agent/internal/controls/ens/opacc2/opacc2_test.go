package opacc2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
)

func run(t *testing.T, collect func(*emit.Emitter) error) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	if err := collect(emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")); err != nil {
		t.Fatal(err)
	}

	var facts []map[string]any
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		var f map[string]any
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		facts = append(facts, f)
	}
	return facts
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// accountFiles writes passwd and group files that know uid and gid 0 and,
// when known is true, the current user's.
func accountFiles(t *testing.T, known bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	passwd, group := "root:x:0:0::/root:/bin/sh\n", "root:x:0:\n"
	if known {
		passwd += fmt.Sprintf("me:x:%d:%d::/home/me:/bin/sh\n", os.Getuid(), os.Getgid())
		group += fmt.Sprintf("me:x:%d:\n", os.Getgid())
	}
	write(t, filepath.Join(dir, "passwd"), passwd, 0o644)
	write(t, filepath.Join(dir, "group"), group, 0o644)
	return filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
}

func TestCollectSweep(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bin/tool"), "x", os.ModeSetuid|0o755)
	write(t, filepath.Join(root, "bin/plain"), "x", 0o755)
	write(t, filepath.Join(root, "bin/shared"), "x", os.ModeSetgid|0o755)
	write(t, filepath.Join(root, "data/open"), "x", 0o666)
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "skip/hidden"), "x", os.ModeSetuid|0o755)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	passwd, group := accountFiles(t, true)
	cfg := SweepConfig{Roots: []string{root}, Prune: []string{filepath.Join(root, "skip")}, PasswdPath: passwd, GroupPath: group, Timeout: time.Minute, MaxRecords: 100}

	facts := run(t, func(e *emit.Emitter) error { return CollectSweep(e, cfg) })

	got := map[string]map[string]any{}
	for _, f := range facts[:len(facts)-1] {
		got[strings.TrimPrefix(f["path"].(string), root)] = f
	}

	if len(got) != 4 {
		t.Fatalf("want 4 special files, got %v", got)
	}
	if f := got["/bin/tool"]; f["suid"] != true || f["mode"] != "4755" || f["kind"] != "file" {
		t.Errorf("suid: %v", f)
	}
	if f := got["/bin/shared"]; f["sgid"] != true || f["suid"] != false {
		t.Errorf("sgid: %v", f)
	}
	if f := got["/data/open"]; f["world_writable"] != true || f["mode"] != "0666" {
		t.Errorf("world-writable file: %v", f)
	}
	if f := got["/tmp"]; f["kind"] != "directory" || f["sticky"] != true || f["world_writable"] != true || f["mode"] != "1777" {
		t.Errorf("sticky dir: %v", f)
	}
	for _, missing := range []string{"/bin/plain", "/skip/hidden", "/link"} {
		if _, ok := got[missing]; ok {
			t.Errorf("%s should not be reported", missing)
		}
	}

	s := facts[len(facts)-1]
	if s["fact"] != "file_sweep_snapshot" || s["status"] != "complete" || s["records_emitted"] != float64(4) || s["unreadable"] != float64(0) {
		t.Errorf("snapshot: %v", s)
	}
}

func TestCollectSweepOwnershipAndLimits(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a"), "x", 0o644)
	write(t, filepath.Join(root, "b"), "x", 0o644)

	// The current user is unknown to these files: everything is unowned.
	passwd, group := accountFiles(t, false)
	cfg := SweepConfig{Roots: []string{root}, PasswdPath: passwd, GroupPath: group, Timeout: time.Minute, MaxRecords: 100}

	facts := run(t, func(e *emit.Emitter) error { return CollectSweep(e, cfg) })
	if len(facts) != 4 || facts[0]["no_owner"] != true || facts[0]["no_group"] != true {
		t.Errorf("unowned: %v", facts)
	}

	// Cut at 2 records: truncated, and the snapshot says so.
	cfg.MaxRecords = 2
	facts = run(t, func(e *emit.Emitter) error { return CollectSweep(e, cfg) })
	if s := facts[len(facts)-1]; s["status"] != "truncated" || s["records_emitted"] != float64(2) {
		t.Errorf("truncated: %v", s)
	}

	// No passwd: nothing can be called unowned, the sweep does not start.
	cfg.PasswdPath = filepath.Join(t.TempDir(), "missing")
	facts = run(t, func(e *emit.Emitter) error { return CollectSweep(e, cfg) })
	if len(facts) != 1 || facts[0]["status"] != "error" || facts[0]["sweep_error"] == nil {
		t.Errorf("no passwd: %v", facts)
	}
}

func TestLocalMounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	write(t, path, `/dev/sda1 / ext4 rw 0 0
proc /proc proc rw 0 0
/dev/sda2 /srv/my\040data xfs rw 0 0
overlay /var/lib/docker/overlay2/x overlay rw 0 0
/dev/sdb1 /var/lib/docker btrfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 / ext4 rw 0 0
`, 0o644)

	// Mount points must exist as directories: use a temp tree for them.
	base := t.TempDir()
	for _, d := range []string{"srv/my data", "data"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(base, "hosts"), "x", 0o644)
	write(t, path, "overlay / overlay rw 0 0\n"+
		"/dev/sda2 "+filepath.Join(base, `srv/my\040data`)+" xfs rw 0 0\n"+
		"/dev/sda3 "+filepath.Join(base, "hosts")+" ext4 rw 0 0\n"+
		"/dev/sdb1 "+filepath.Join(base, "data")+" ext4 rw 0 0\n"+
		"proc /proc proc rw 0 0\n"+
		"overlay /var/lib/docker/overlay2/x overlay rw 0 0\n", 0o644)

	roots, err := localMounts(path, append(DefaultPrune, filepath.Join(base, "data")))
	want := "/|" + filepath.Join(base, "srv/my data")
	if err != nil || strings.Join(roots, "|") != want {
		t.Errorf("roots %q %v, want %s", roots, err, want)
	}
}

func TestCollectUmask(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "login.defs"), "# UMASK 000\nUMASK\t022\n", 0o644)
	write(t, filepath.Join(dir, "profile"), "umask\numask -S\numask 27 # restrictive\nif x; then umask 0077; fi\n[ $UID -gt 199 ] && umask 002\n", 0o644)
	write(t, filepath.Join(dir, "profile.d/a.sh"), "umask u=rwx,g=rx,o=\numask $DEFAULT\n", 0o644)
	write(t, filepath.Join(dir, "profile.d/notes.txt"), "umask 000\n", 0o644)

	cfg := UmaskConfig{Files: []string{filepath.Join(dir, "login.defs"), filepath.Join(dir, "profile"), filepath.Join(dir, "missing")}, ProfileDir: filepath.Join(dir, "profile.d")}
	facts := run(t, func(e *emit.Emitter) error { return CollectUmask(e, cfg) })

	sources := facts[0]["sources"].([]any)
	if len(sources) != 4 {
		t.Fatalf("want 4 sources (txt ignored), got %v", sources)
	}
	got, _ := json.Marshal(sources)
	for _, want := range []string{
		`"umasks":["022"]`,
		`"umasks":["027","077","002"]`,
		`"status":"absent"`,
		`"uninterpretable":["u=rwx,g=rx,o=","$DEFAULT"]`,
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestCollectSudoers(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "sudoers"), `Defaults env_reset
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
	write(t, filepath.Join(dir, "sudoers.d/ops"), "%#1500 ALL = ALL\n", 0o440)
	write(t, filepath.Join(dir, "sudoers.d/ops.dpkg-old"), "eve ALL = ALL\n", 0o440)
	write(t, filepath.Join(dir, "sudoers.d/backup~"), "eve ALL = ALL\n", 0o440)

	facts := run(t, func(e *emit.Emitter) error {
		return CollectSudoers(e, SudoersConfig{Path: filepath.Join(dir, "sudoers")})
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

	// No sudoers: sudo is not installed, nobody has it.
	facts = run(t, func(e *emit.Emitter) error {
		return CollectSudoers(e, SudoersConfig{Path: filepath.Join(dir, "nothing")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" || facts[0]["blind_spots"] != float64(0) {
		t.Errorf("absent: %v", facts)
	}
}

func TestSudoersReauthentication(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "sudoers"), `Defaults env_reset, timestamp_timeout=-1
Defaults:backup !authenticate
Defaults env_keep += "LANG, LC_ALL"
Cmnd_Alias SVC = /usr/bin/systemctl restart nginx, /usr/bin/systemctl reload nginx
Cmnd_Alias NESTED = SVC, !/usr/bin/su
ana ALL = (root) NOPASSWD: /usr/bin/apt, PASSWD: /usr/bin/vi, /bin/ls
ops ALL = (ALL : ALL) CWD=/tmp NOPASSWD:SETENV: NESTED, ALL, !/usr/bin/passwd
bob ALL = NOPASSWD: UNDEFINED
eve ALL = /usr/bin/who, NOPASSWD: /usr/bin/x\, y
`, 0o440)

	facts := run(t, func(e *emit.Emitter) error {
		return CollectSudoers(e, SudoersConfig{Path: filepath.Join(dir, "sudoers")})
	})

	got := map[string]string{}
	for _, f := range facts[:len(facts)-1] {
		cmds, _ := json.Marshal(f["nopasswd_commands"])
		got[f["subject"].(string)] = string(cmds)
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

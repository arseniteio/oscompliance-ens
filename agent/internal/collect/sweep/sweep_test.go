package sweep

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func accountFiles(t *testing.T, known bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	passwd, group := "root:x:0:0::/root:/bin/sh\n", "root:x:0:\n"
	if known {
		passwd += fmt.Sprintf("me:x:%d:%d::/home/me:/bin/sh\n", os.Getuid(), os.Getgid())
		group += fmt.Sprintf("me:x:%d:\n", os.Getgid())
	}
	collecttest.WriteFile(t, filepath.Join(dir, "passwd"), passwd, 0o644)
	collecttest.WriteFile(t, filepath.Join(dir, "group"), group, 0o644)
	return filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
}

func TestCollectSweep(t *testing.T) {
	root := t.TempDir()
	collecttest.WriteFile(t, filepath.Join(root, "bin/tool"), "x", os.ModeSetuid|0o755)
	collecttest.WriteFile(t, filepath.Join(root, "bin/plain"), "x", 0o755)
	collecttest.WriteFile(t, filepath.Join(root, "bin/shared"), "x", os.ModeSetgid|0o755)
	collecttest.WriteFile(t, filepath.Join(root, "data/open"), "x", 0o666)
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "tmp"), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	collecttest.WriteFile(t, filepath.Join(root, "skip/hidden"), "x", os.ModeSetuid|0o755)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}

	passwd, group := accountFiles(t, true)
	cfg := Config{Roots: []string{root}, Prune: []string{filepath.Join(root, "skip")}, PasswdPath: passwd, GroupPath: group, Timeout: time.Minute, MaxRecords: 100}

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })

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
	collecttest.WriteFile(t, filepath.Join(root, "a"), "x", 0o644)
	collecttest.WriteFile(t, filepath.Join(root, "b"), "x", 0o644)

	passwd, group := accountFiles(t, false)
	cfg := Config{Roots: []string{root}, PasswdPath: passwd, GroupPath: group, Timeout: time.Minute, MaxRecords: 100}

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })
	if len(facts) != 4 || facts[0]["no_owner"] != true || facts[0]["no_group"] != true {
		t.Errorf("unowned: %v", facts)
	}

	cfg.MaxRecords = 2
	facts = collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })
	if s := facts[len(facts)-1]; s["status"] != "truncated" || s["records_emitted"] != float64(2) {
		t.Errorf("truncated: %v", s)
	}

	cfg.PasswdPath = filepath.Join(t.TempDir(), "missing")
	facts = collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })
	if len(facts) != 1 || facts[0]["status"] != "error" || facts[0]["sweep_error"] == nil {
		t.Errorf("no passwd: %v", facts)
	}
}

func TestLocalMounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mounts")
	collecttest.WriteFile(t, path, `/dev/sda1 / ext4 rw 0 0
proc /proc proc rw 0 0
/dev/sda2 /srv/my\040data xfs rw 0 0
overlay /var/lib/docker/overlay2/x overlay rw 0 0
/dev/sdb1 /var/lib/docker btrfs rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/sda1 / ext4 rw 0 0
`, 0o644)

	base := t.TempDir()
	for _, d := range []string{"srv/my data", "data"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	collecttest.WriteFile(t, filepath.Join(base, "hosts"), "x", 0o644)
	collecttest.WriteFile(t, path, "overlay / overlay rw 0 0\n"+
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

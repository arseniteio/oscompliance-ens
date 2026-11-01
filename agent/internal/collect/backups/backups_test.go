package backups

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func TestCollect(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "etc", ".git", "logs", "HEAD"),
		"0000 1111 root <root@h> 1761000000 +0000\tcommit (initial): first\n1111 2222 root <root@h> 1761700000 +0000\tcommit: daily autocommit\n")
	old := filepath.Join(dir, "backups", "etc-1.tar.gz")
	collecttest.Write(t, old, "x")
	collecttest.Write(t, filepath.Join(dir, "backups", "etc-2.tar.gz"), "yy")
	if err := os.Chtimes(old, time.Unix(1700000000, 0), time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(old, 0o644); err != nil {
		t.Fatal(err)
	}
	collecttest.Write(t, filepath.Join(dir, "nas", "vm", "100", "index.json"), "{}")
	keyFile := filepath.Join(dir, "key.json")
	collecttest.Write(t, keyFile, "k")
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}

	mounts := []mount{{point: "/", fstype: "ext4", device: "/dev/sda1"}, {point: filepath.Join(dir, "nas"), fstype: "nfs4", device: "nas01:/copias"}}
	sources := []string{"git:" + filepath.Join(dir, "etc"), filepath.Join(dir, "backups", "etc-*.tar.gz"), filepath.Join(dir, "none", "*.tar"), filepath.Join(dir, "nas")}
	keys := []string{keyFile, filepath.Join(dir, "missing.key")}
	f := collecttest.Facts(t, func(e *emit.Emitter) error { return collect(e, sources, keys, true, mounts) })[0]

	got := f["sources"].([]any)
	if git := got[0].(map[string]any); git["newest"] != "2025-10-29T01:06:40Z" || git["oldest"] != "2025-10-20T22:40:00Z" || git["files"] != 2.0 {
		t.Errorf("git: %v", git)
	}
	files := got[1].(map[string]any)
	if files["status"] != "read" || files["oldest"] != "2023-11-14T22:13:20Z" || files["files"] != 2.0 || files["bytes"] != 3.0 || files["newest_bytes"] != 2.0 || files["other_readable"] == nil {
		t.Errorf("pattern: %v", files)
	}
	if files["filesystem"] != "ext4" || files["mode"] == nil {
		t.Errorf("pattern root: %v", files)
	}
	if none := got[2].(map[string]any); none["status"] != "absent" {
		t.Errorf("no copy: %v", none)
	}
	if nas := got[3].(map[string]any); nas["filesystem"] != "nfs4" || nas["device"] != "nas01:/copias" || nas["files"] != 1.0 {
		t.Errorf("directory on a remote mount: %v", nas)
	}

	k := f["key_files"].([]any)
	if first := k[0].(map[string]any); first["mode"] != "0600" {
		t.Errorf("key: %v", first)
	}
	if second := k[1].(map[string]any); second["status"] != "absent" {
		t.Errorf("missing key: %v", second)
	}

	if f := collecttest.Facts(t, func(e *emit.Emitter) error { return collect(e, nil, nil, false, nil) })[0]; f["status"] != "absent" {
		t.Errorf("not configured: %v", f)
	}
}

func TestMounts(t *testing.T) {

	path := filepath.Join(t.TempDir(), "mountinfo")
	collecttest.Write(t, path, "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"+
		"40 22 0:50 / /mnt/my\\040nas rw - cifs //nas/copias rw\n")

	m, ok := mountOf("/mnt/my nas/daily", readMounts(path))
	if !ok || m.fstype != "cifs" || m.device != "//nas/copias" {
		t.Errorf("got %+v", m)
	}
	if m, _ := mountOf("/var/backups", readMounts(path)); m.fstype != "ext4" {
		t.Errorf("root: %+v", m)
	}
}

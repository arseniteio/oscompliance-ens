package device

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func TestCollect(t *testing.T) {

	root := t.TempDir()
	at := func(p string) string { return filepath.Join(root, p) }
	collecttest.Write(t, at("/sys/class/dmi/id/chassis_type"), "10\n")
	collecttest.Write(t, at("/usr/sbin/gdm3"), "")
	collecttest.Write(t, at("/etc/dconf/db/local.d/00-screensaver"), "[org/gnome/desktop/session]\nidle-delay=uint32 900\n\n[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 0\n")
	collecttest.Write(t, at("/etc/dconf/db/local.d/locks/screensaver"), "/org/gnome/desktop/session/idle-delay\n")
	collecttest.Write(t, at("/etc/profile.d/tmout.sh"), "TMOUT=1800\nreadonly TMOUT\nexport TMOUT\n")
	collecttest.Write(t, at("/etc/bash.bashrc"), "export TMOUT=3600\n")
	collecttest.Write(t, at("/etc/systemd/logind.conf.d/idle.conf"), "[Login]\nStopIdleSessionSec=1h\n")
	collecttest.Write(t, at("/proc/self/mounts"), "/dev/mapper/vg-root / ext4 rw 0 0\n/dev/sda1 /boot ext4 rw 0 0\n")
	collecttest.Write(t, at("/etc/resolv.conf"), "nameserver 127.0.0.53\noptions edns0\n")
	collecttest.Write(t, at("/run/systemd/resolve/resolv.conf"), "nameserver 10.0.0.53\nnameserver 10.0.0.54\n")
	collecttest.Write(t, at("/sys/class/block/dm-1/dm/uuid"), "LVM-abc")
	collecttest.Write(t, at("/sys/class/block/dm-0/dm/uuid"), "CRYPT-LUKS2-abc-sda3_crypt")
	if err := os.MkdirAll(at("/sys/class/block/dm-1/slaves/dm-0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(at("/dev/mapper"), 0o755); err != nil {
		t.Fatal(err)
	}
	collecttest.Write(t, at("/dev/dm-1"), "")
	if err := os.Symlink("../dm-1", at("/dev/mapper/vg-root")); err != nil {
		t.Fatal(err)
	}

	f := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, Config{Root: root}) })[0]

	if f["portable"] != true || f["graphical"] != true || f["lock_idle_delay_seconds"] != 900.0 || f["lock_enabled"] != true || f["lock_delay_seconds"] != 0.0 {
		t.Errorf("lock: %v", f)
	}
	if f["shell_timeout_seconds"] != 1800.0 || f["shell_timeout_readonly"] != true || f["logind_idle_seconds"] != 3600.0 {
		t.Errorf("timeouts: %v", f)
	}
	if f["root_device"] != "dm-1" || f["root_encrypted"] != true {
		t.Errorf("encryption: %v", f)
	}
	if r := f["dns_resolvers"].([]any); len(r) != 2 || r[0] != "10.0.0.53" {
		t.Errorf("resolvers: %v", f)
	}

	bare := t.TempDir()
	collecttest.Write(t, filepath.Join(bare, "/proc/self/mounts"), "overlay / overlay rw 0 0\n")
	g := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, Config{Root: bare}) })[0]
	if g["graphical"] != false || g["root_encrypted"] != false || g["lock_enabled"] != nil {
		t.Errorf("bare: %v", g)
	}
}

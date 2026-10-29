package virtualization

import (
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func TestCollect(t *testing.T) {

	dir := t.TempDir()
	run := func(cfg Config) map[string]any {
		return collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, cfg) })[0]
	}

	collecttest.Write(t, filepath.Join(dir, "dmi", "sys_vendor"), "QEMU\n")
	collecttest.Write(t, filepath.Join(dir, "dmi", "product_name"), "Standard PC (Q35 + ICH9, 2009)\n")
	if f := run(Config{DMI: filepath.Join(dir, "dmi"), CPUInfo: filepath.Join(dir, "none")}); f["virtual"] != true || f["source"] != "dmi" || f["vendor"] != "QEMU" {
		t.Errorf("firmware: %v", f)
	}

	collecttest.Write(t, filepath.Join(dir, "vm"), "processor : 0\nflags : fpu vme hypervisor lm\n")
	if f := run(Config{DMI: filepath.Join(dir, "none"), CPUInfo: filepath.Join(dir, "vm")}); f["virtual"] != true || f["source"] != "cpuinfo" {
		t.Errorf("cpu flag: %v", f)
	}

	collecttest.Write(t, filepath.Join(dir, "metal"), "processor : 0\nflags : fpu vme lm\n")
	if f := run(Config{DMI: filepath.Join(dir, "none"), CPUInfo: filepath.Join(dir, "metal")}); f["virtual"] != false || f["status"] != "read" {
		t.Errorf("physical: %v", f)
	}

	if f := run(Config{DMI: filepath.Join(dir, "none"), CPUInfo: filepath.Join(dir, "none")}); f["status"] != "unreadable" {
		t.Errorf("nothing to read: %v", f)
	}
}

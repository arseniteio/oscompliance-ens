package virtualization

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	DetectVirt string
	DMI        string
	CPUInfo    string
}

var Default = Config{DetectVirt: "/usr/bin/systemd-detect-virt", DMI: "/sys/class/dmi/id", CPUInfo: "/proc/cpuinfo"}

var hypervisors = []string{"QEMU", "KVM", "VMware", "VirtualBox", "innotek", "Xen", "Virtual Machine", "Bochs", "Parallels", "Amazon EC2", "Google Compute Engine"}

func Collect(e *emit.Emitter, cfg Config) error {

	v := fact.Virtualization{Envelope: e.Envelope(fact.VirtualizationFact), Status: fact.SourceRead}
	v.Vendor = firstLine(cfg.DMI + "/sys_vendor")
	v.Product = firstLine(cfg.DMI + "/product_name")

	if host.Exists(cfg.DetectVirt) {
		if out, err := host.Run(cfg.DetectVirt, "--vm"); err == nil {
			if p := strings.TrimSpace(out); p != "" && p != "none" {
				v.Virtual, v.Platform, v.Source = true, p, "systemd-detect-virt"
				return e.Emit(v)
			}
		}
	}

	firmware := v.Vendor + " " + v.Product
	for _, h := range hypervisors {
		if strings.Contains(firmware, h) {
			v.Virtual, v.Platform, v.Source = true, "unknown", "dmi"
			return e.Emit(v)
		}
	}

	cpu, err := fsread.ReadFile(cfg.CPUInfo)
	switch {
	case err == nil:
		v.Source = "cpuinfo"
		for _, line := range strings.Split(string(cpu), "\n") {
			if strings.HasPrefix(line, "flags") && strings.Contains(" "+line+" ", " hypervisor ") {
				v.Virtual, v.Platform = true, "unknown"
				break
			}
		}
	case v.Vendor == "" && errors.Is(err, fs.ErrNotExist):
		v.Status, v.Error = fact.SourceUnreadable, "no systemd-detect-virt, DMI or "+cfg.CPUInfo
	case v.Vendor == "":
		v.Status, v.Error = fact.SourceUnreadable, err.Error()
	default:
		v.Source = "dmi"
	}

	return e.Emit(v)
}

func firstLine(path string) string {
	data, err := fsread.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}

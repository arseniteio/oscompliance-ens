package hostprofile

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

const (
	RoleManager     = "manager"
	RoleServer      = "server"
	RoleWorkstation = "workstation"
)

type Profile struct {
	Timestamp     string        `json:"@timestamp"`
	Agent         verdict.Agent `json:"agent"`
	Hostname      string        `json:"hostname,omitempty"`
	Groups        []string      `json:"groups"`
	OS            OS            `json:"os"`
	Distro        string        `json:"distro,omitempty"`
	Family        string        `json:"family,omitempty"`
	Role          string        `json:"role"`
	Services      []string      `json:"services"`
	Signals       []Signal      `json:"signals"`
	EngineVersion string        `json:"engine_version"`
}

type OS struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Platform     string `json:"platform,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

type Signal struct {
	Field string `json:"field"`
	Value string `json:"value"`
	From  string `json:"from"`
}

func Build(agent verdict.Agent, groups []string, inv *source.HostInventory, signals catalog.HostSignals, now time.Time, engineVersion string) Profile {

	p := Profile{Timestamp: now.UTC().Format(time.RFC3339), Agent: agent, Groups: slices.Sorted(slices.Values(groups)), Services: []string{}, Signals: []Signal{}, EngineVersion: engineVersion}
	if inv == nil {
		inv = &source.HostInventory{}
	}
	p.Hostname = inv.Hostname
	p.OS = OS{Name: inv.OS, Version: inv.Version, Platform: inv.Platform, Architecture: inv.Architecture}

	if d, from, ok := distro(inv, signals.Distros); ok {
		p.Distro, p.Family = d.ID, d.Family
		if v := version(inv.Version, d.Version); v != "" {
			p.Distro += "-" + v
		}
		p.Signals = append(p.Signals, Signal{Field: "distro", Value: p.Distro, From: from})
	}

	packages := slices.Sorted(slices.Values(inv.Packages))

	p.Role = RoleServer
	if agent.ID == source.ManagerID {
		p.Role = RoleManager
		p.Signals = append(p.Signals, Signal{Field: "role", Value: RoleManager, From: "agent:" + source.ManagerID})
	} else {
		for _, r := range signals.Roles {
			if pkg, ok := firstMatch(r, packages); ok {
				p.Role = r.ID
				p.Signals = append(p.Signals, Signal{Field: "role", Value: r.ID, From: "package:" + pkg})
				break
			}
		}
	}

	found := map[string]string{}
	for _, s := range signals.Services {
		if pkg, ok := firstMatch(s, packages); ok {
			found[s.ID] = pkg
		}
	}
	for _, s := range signals.Services {
		pkg, ok := found[s.ID]
		if !ok || slices.ContainsFunc(s.Unless, func(u string) bool { _, hit := found[u]; return hit }) {
			continue
		}
		p.Services = append(p.Services, s.ID)
		p.Signals = append(p.Signals, Signal{Field: "service", Value: s.ID, From: "package:" + pkg})
	}

	return p
}

func distro(inv *source.HostInventory, distros []catalog.DistroSignal) (catalog.DistroSignal, string, bool) {

	platform := strings.ToLower(strings.TrimSpace(inv.Platform))
	if platform != "" {
		for _, d := range distros {
			if slices.Contains(d.Platforms, platform) {
				return d, "os.platform:" + platform, true
			}
		}
	}

	name := strings.ToLower(inv.OS)
	if name != "" {
		for _, d := range distros {
			for _, n := range d.Names {
				if strings.Contains(name, n) {
					return d, "os.name:" + inv.OS, true
				}
			}
		}
	}

	return catalog.DistroSignal{}, "", false
}

func version(full, precision string) string {

	parts := strings.FieldsFunc(full, func(r rune) bool { return r == '.' || r == ' ' || r == '-' })
	if len(parts) == 0 || !isNumber(parts[0]) {
		return ""
	}
	if precision == "major.minor" && len(parts) > 1 && isNumber(parts[1]) {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}

func isNumber(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

func firstMatch(sig catalog.PackageSignal, packages []string) (string, bool) {
	for _, pkg := range packages {
		if sig.Match(pkg) {
			return pkg, true
		}
	}
	return "", false
}

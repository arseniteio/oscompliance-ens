package catalog

import (
	"slices"
	"strings"
)

type HostSignals struct {
	Distros  []DistroSignal  `json:"distros"`
	Roles    []PackageSignal `json:"roles"`
	Services []PackageSignal `json:"services"`
}

type DistroSignal struct {
	ID        string   `json:"id"`
	Family    string   `json:"family"`
	Platforms []string `json:"platforms"`
	Names     []string `json:"names"`
	Version   string   `json:"version"`
	Role      string   `json:"role,omitempty"`
}

type PackageSignal struct {
	ID       string   `json:"id"`
	Packages []string `json:"packages"`
	Unless   []string `json:"unless,omitempty"`
}

var hostSignals HostSignals

func loadHostSignals() {
	if err := decodeStrict("host-signals.json", &hostSignals); err != nil {
		panic(err)
	}
}

func Signals() HostSignals { return hostSignals }

func (s HostSignals) PackageNames() (exact, prefixes []string) {
	for _, sig := range slices.Concat(s.Roles, s.Services) {
		for _, p := range sig.Packages {
			if name, ok := strings.CutSuffix(p, "*"); ok {
				prefixes = append(prefixes, name)
			} else {
				exact = append(exact, p)
			}
		}
	}
	slices.Sort(exact)
	slices.Sort(prefixes)
	return slices.Compact(exact), slices.Compact(prefixes)
}

func (p PackageSignal) Match(installed string) bool {
	for _, want := range p.Packages {
		if name, ok := strings.CutSuffix(want, "*"); ok {
			if strings.HasPrefix(installed, name) {
				return true
			}
		} else if installed == want {
			return true
		}
	}
	return false
}

// Package packages lists the packages installed on request: the package manager keeps them apart from
// the dependencies it pulled in.
package packages

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	AptMark string
	DNF     string
}

var Default = Config{AptMark: "/usr/bin/apt-mark", DNF: "/usr/bin/dnf"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.PackageSelection{Envelope: e.Envelope(fact.PackageSelectionFact), Status: fact.SourceRead, Packages: []string{}}

	var out string
	var err error
	switch {
	case host.Exists(cfg.AptMark):
		s.Manager = "apt"
		out, err = host.Run(cfg.AptMark, "showmanual")
	case host.Exists(cfg.DNF):
		s.Manager = "dnf"
		out, err = host.Run(cfg.DNF, "repoquery", "--userinstalled", "--qf", "%{name}", "-q")
	default:
		s.Manager = "none"
		return e.Emit(s)
	}
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}

	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			s.Packages = append(s.Packages, name)
		}
	}
	slices.Sort(s.Packages)
	s.Packages = slices.Compact(s.Packages)

	return e.Emit(s)
}

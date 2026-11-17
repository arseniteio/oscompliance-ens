package winpackages

import (
	_ "embed"
	"slices"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed packages.ps1
var script string

const Manager = "windows-installer"

type output struct {
	Packages []string `json:"packages"`
	Features []string `json:"features"`
}

func Collect(e *emit.Emitter, run winps.Runner) error {

	s := fact.PackageSelection{Envelope: e.Envelope(fact.PackageSelectionFact), Manager: Manager, Status: fact.SourceRead, Packages: []string{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}

	s.Packages = append(append(s.Packages, out.Packages...), out.Features...)
	slices.Sort(s.Packages)
	s.Packages = slices.Compact(s.Packages)
	return e.Emit(s)
}

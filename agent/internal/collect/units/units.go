// Package units lists the systemd services running on the machine.
package units

import (
	"os"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	Systemctl string
	// Systemd's runtime directory: a machine without it does not run systemd, whatever is installed.
	RunDir string
}

var Default = Config{Systemctl: "/usr/bin/systemctl", RunDir: "/run/systemd/system"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.UnitSnapshot{Envelope: e.Envelope(fact.UnitSnapshotFact), Status: fact.SourceRead, Units: []string{}, Failed: []string{}}

	if info, err := os.Stat(cfg.RunDir); !host.Exists(cfg.Systemctl) || err != nil || !info.IsDir() {
		s.Status = fact.SourceAbsent
		return e.Emit(s)
	}

	for _, list := range []struct {
		state string
		into  *[]string
	}{{"running", &s.Units}, {"failed", &s.Failed}} {
		out, err := host.Run(cfg.Systemctl, "list-units", "--type=service", "--state="+list.state, "--no-legend", "--plain", "--no-pager")
		if err != nil {
			s.Status, s.Error = fact.SourceError, err.Error()
			return e.Emit(s)
		}
		*list.into = parse(out)
	}
	return e.Emit(s)
}

// parse takes the first column of `systemctl list-units --plain --no-legend`.
func parse(out string) []string {
	units := []string{}
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			units = append(units, f[0])
		}
	}
	slices.Sort(units)
	return slices.Compact(units)
}

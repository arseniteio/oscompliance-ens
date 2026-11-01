// Package updates tells what the package manager would upgrade now, without downloading anything, and how
// old the package lists it decides from are.
package updates

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	AptGet string
	Lists  string
}

var Default = Config{AptGet: "/usr/bin/apt-get", Lists: "/var/lib/apt/lists"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.UpdateStatus{Envelope: e.Envelope(fact.UpdateStatusFact), Status: fact.SourceRead}

	if !host.Exists(cfg.AptGet) {
		s.Manager = "none"
		return e.Emit(s)
	}
	s.Manager = "apt"

	if t := newest(cfg.Lists); !t.IsZero() {
		s.ListsUpdated = t.UTC().Format(time.RFC3339)
	}

	out, err := host.Run(cfg.AptGet, "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}
	s.Pending, s.Security = count(out)

	return e.Emit(s)
}

// count reads the `Inst` lines of a simulated upgrade: `Inst pkg [old] (new pocket [arch])`.
func count(out string) (pending, security int) {
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		pending++
		if strings.Contains(line, "-security") {
			security++
		}
	}
	return pending, security
}

func newest(dir string) time.Time {
	var t time.Time
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := os.Stat(filepath.Join(dir, e.Name())); err == nil && info.Mode().IsRegular() && info.ModTime().After(t) {
			t = info.ModTime()
		}
	}
	return t
}

// Package timesync reports how the machine keeps its clock: chrony when it runs, else systemd-timesyncd.
package timesync

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/host"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

type Config struct {
	Chronyc     string
	ChronyConfs []string
	Timedatectl string
}

var Default = Config{Chronyc: "/usr/bin/chronyc", ChronyConfs: []string{"/etc/chrony/chrony.conf", "/etc/chrony.conf", "/etc/chrony/conf.d/*.conf", "/etc/chrony/sources.d/*.sources"}, Timedatectl: "/usr/bin/timedatectl"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.TimeSync{Envelope: e.Envelope(fact.TimeSyncFact), Tool: "none", Status: fact.SourceRead, Sources: []string{}}

	if host.Exists(cfg.Chronyc) {
		if tracking, err := host.Run(cfg.Chronyc, "-n", "tracking"); err == nil {
			s.Tool = "chrony"
			s.Synchronised, s.Offset = parseTracking(tracking)
			if sources, err := host.Run(cfg.Chronyc, "-n", "sources"); err == nil {
				s.Sources = parseSources(sources)
			}
			s.Authenticated = authenticated(cfg.ChronyConfs)
			return e.Emit(s)
		}
	}

	if host.Exists(cfg.Timedatectl) {
		if out, err := host.Run(cfg.Timedatectl, "show", "-p", "NTPSynchronized", "-p", "NTP"); err == nil {
			s.Tool = "timesyncd"
			s.Synchronised = strings.Contains(out, "NTPSynchronized=yes")
			if status, err := host.Run(cfg.Timedatectl, "show-timesync", "-p", "ServerName", "--value"); err == nil && strings.TrimSpace(status) != "" {
				s.Sources = []string{strings.TrimSpace(status)}
			}
		}
	}

	return e.Emit(s)
}

// parseTracking reads `Leap status : Normal` and `System time : 0.000012 seconds fast of NTP time`.
func parseTracking(out string) (synchronised bool, offset float64) {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		switch key {
		case "Leap status":
			synchronised = value != "Not synchronised"
		case "System time":
			f := strings.Fields(value)
			if len(f) > 0 {
				offset, _ = strconv.ParseFloat(f[0], 64)
				if len(f) > 2 && f[2] == "slow" {
					offset = -offset
				}
			}
		}
	}
	return synchronised, offset
}

// parseSources keeps the address of each `^*` (selected) or `^+` (combined) source.
func parseSources(out string) []string {
	sources := []string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && (strings.HasPrefix(f[0], "^*") || strings.HasPrefix(f[0], "^+")) {
			sources = append(sources, f[1])
		}
	}
	return sources
}

// authenticated says whether a chrony source asks NTS or a symmetric key.
func authenticated(patterns []string) bool {
	for _, pattern := range patterns {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			data, err := fsread.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 || (fields[0] != "server" && fields[0] != "pool") {
					continue
				}
				for _, opt := range fields[2:] {
					if opt == "nts" || opt == "key" {
						return true
					}
				}
			}
		}
	}
	return false
}

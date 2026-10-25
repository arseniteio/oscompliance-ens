package sysconf

import (
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// AuditKey marks the watches the agent loads; Wazuh's audit decoder gives
// it as audit.key.
const AuditKey = "oscompliance_obj"

// AuditConfig says where auditctl and the shared path list are.
type AuditConfig struct {
	Auditctl    string
	SharedPaths string
}

// CollectAuditWatches loads a watch (read, write, execute, attribute
// change) for each audit_watches path of the shared oscompliance.json that
// is not loaded yet, then emits the audit_watch_snapshot. It never removes
// a rule: what the administrator loaded stays.
func CollectAuditWatches(e *emit.Emitter, cfg AuditConfig) error {

	snapshot := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	paths, _, err := readSharedPaths(cfg.SharedPaths)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, cfg.SharedPaths+": "+err.Error()
		return e.Emit(snapshot)
	}
	snapshot.Wanted = append(snapshot.Wanted, paths.AuditWatches...)

	if _, err := os.Stat(cfg.Auditctl); errors.Is(err, fs.ErrNotExist) {
		snapshot.Auditd = fact.AuditdAbsent
		return e.Emit(snapshot)
	}

	// "enabled 0" or no daemon pid: nothing is recorded.
	status, err := runCommand(cfg.Auditctl, "-s")
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}
	if !auditRunning(status) {
		snapshot.Auditd = fact.AuditdStopped
		return e.Emit(snapshot)
	}

	loaded, err := loadedWatches(cfg.Auditctl)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}

	for _, p := range paths.AuditWatches {

		if !slices.Contains(loaded, p) {
			if _, err := runCommand(cfg.Auditctl, "-w", p, "-p", "rwxa", "-k", AuditKey); err != nil {
				snapshot.Failed = append(snapshot.Failed, p+": "+err.Error())
				continue
			}
		}
		snapshot.Loaded = append(snapshot.Loaded, p)
	}

	return e.Emit(snapshot)
}

// auditRunning reads auditctl -s: auditing enabled and a daemon attached.
func auditRunning(status string) bool {

	enabled, pid := false, false

	for _, line := range strings.Split(status, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch k {
		case "enabled":
			enabled = v != "0"
		case "pid":
			pid = v != "0" && v != ""
		}
	}

	return enabled && pid
}

// loadedWatches lists the paths of the loaded watches with our key, in
// either form auditctl -l prints them: "-w /srv/datos -p rwxa -k KEY" or
// "-a always,exit -F dir=/srv/datos -F perm=rwxa -F key=KEY".
func loadedWatches(auditctl string) ([]string, error) {

	out, err := runCommand(auditctl, "-l")
	if err != nil {
		return nil, err
	}

	return parseWatches(out), nil
}

func parseWatches(listing string) []string {

	var paths []string

	for _, line := range strings.Split(listing, "\n") {

		f := strings.Fields(line)

		if len(f) >= 2 && f[0] == "-w" && slices.Contains(f, "-k") && f[len(f)-1] == AuditKey {
			paths = append(paths, f[1])
			continue
		}

		if !slices.Contains(f, "key="+AuditKey) {
			continue
		}
		for _, field := range f {
			if v, ok := strings.CutPrefix(field, "dir="); ok {
				paths = append(paths, v)
			} else if v, ok := strings.CutPrefix(field, "path="); ok {
				paths = append(paths, v)
			}
		}
	}

	return paths
}

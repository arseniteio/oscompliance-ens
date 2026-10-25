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

// AuditKeys are the keys of the watches the agent loads, one per kind of
// access: the kernel classifies each access by the permission it uses, and
// Wazuh's audit decoder gives the key as audit.key. A watch per permission
// tells the engine the kind without decoding syscalls and flags.
var AuditKeys = []struct{ Perm, Key string }{
	{"r", "oscompliance_read"},
	{"w", "oscompliance_write"},
	{"x", "oscompliance_exec"},
	{"a", "oscompliance_attr"},
}

// execKey is the key of the execution watches of exec_watches; it is the
// same as the x watch of a path, so either reads as an execution.
const execKey = "oscompliance_exec"

// AuditConfig says where auditctl and the shared path list are.
type AuditConfig struct {
	Auditctl    string
	SharedPaths string
}

// CollectAuditWatches loads the four watches (read, write, execute,
// attribute change) of each audit_watches path of the shared
// oscompliance.json that are not loaded yet, then emits the
// audit_watch_snapshot. It never removes a rule: what the administrator
// loaded stays.
func CollectAuditWatches(e *emit.Emitter, cfg AuditConfig) error {

	snapshot := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	paths, _, err := readSharedPaths(cfg.SharedPaths)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, cfg.SharedPaths+": "+err.Error()
		return e.Emit(snapshot)
	}
	snapshot.Wanted = append(snapshot.Wanted, paths.AuditWatches...)
	snapshot.ExecWanted = append(snapshot.ExecWanted, paths.ExecWatches...)

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

		ok := true
		for _, w := range AuditKeys {
			if slices.Contains(loaded, p+" "+w.Key) {
				continue
			}
			if _, err := runCommand(cfg.Auditctl, "-w", p, "-p", w.Perm, "-k", w.Key); err != nil {
				snapshot.Failed = append(snapshot.Failed, p+" "+w.Perm+": "+err.Error())
				ok = false
			}
		}

		if ok {
			snapshot.Loaded = append(snapshot.Loaded, p)
		}
	}

	// Binaries: their executions only.
	for _, b := range paths.ExecWatches {

		if !slices.Contains(loaded, b+" "+execKey) {
			if _, err := runCommand(cfg.Auditctl, "-w", b, "-p", "x", "-k", execKey); err != nil {
				snapshot.Failed = append(snapshot.Failed, b+" x: "+err.Error())
				continue
			}
		}
		snapshot.ExecLoaded = append(snapshot.ExecLoaded, b)
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

// loadedWatches lists the loaded watches with one of our keys as "path key",
// in either form auditctl -l prints them: "-w /srv/datos -p r -k KEY" or
// "-a always,exit -F dir=/srv/datos -F perm=r -F key=KEY".
func loadedWatches(auditctl string) ([]string, error) {

	out, err := runCommand(auditctl, "-l")
	if err != nil {
		return nil, err
	}

	return parseWatches(out), nil
}

func parseWatches(listing string) []string {

	var out []string

	for _, line := range strings.Split(listing, "\n") {

		f := strings.Fields(line)

		for _, w := range AuditKeys {

			if len(f) >= 2 && f[0] == "-w" && slices.Contains(f, "-k") && f[len(f)-1] == w.Key {
				out = append(out, f[1]+" "+w.Key)
				continue
			}

			if !slices.Contains(f, "key="+w.Key) {
				continue
			}
			for _, field := range f {
				if v, ok := strings.CutPrefix(field, "dir="); ok {
					out = append(out, v+" "+w.Key)
				} else if v, ok := strings.CutPrefix(field, "path="); ok {
					out = append(out, v+" "+w.Key)
				}
			}
		}
	}

	return out
}

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/host"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// Keys are the keys of the watches the agent loads, one per kind of
// access: the kernel classifies each access by the permission it uses, and
// Wazuh's audit decoder gives the key as audit.key. A watch per permission
// tells the engine the kind without decoding syscalls and flags.
var Keys = []struct{ Perm, Key string }{
	{"r", "oscompliance_read"},
	{"w", "oscompliance_write"},
	{"x", "oscompliance_exec"},
	{"a", "oscompliance_attr"},
}

// execKey is the key of the execution watches of exec_watches; it is the
// same as the x watch of a path, so either reads as an execution.
const execKey = "oscompliance_exec"

// permKey marks the fixed rules of op.acc.4 EV-04: who changes rights.
const permKey = "oscompliance_perm"

// permRules record, independently of any parameter, every change of mode,
// owner or extended attributes made by a person (login uid 1000 and
// above), and every write to the account and sudo files. The syscalls
// differ by architecture: arm64 has no chmod, chown or lchown, and 32-bit
// calls exist on amd64 only. v1 covered 64-bit amd64 only and left loading
// the rules to the administrator.
func permRules(arch string) [][]string {

	syscalls := [][]string{
		{"fchmod,fchmodat"},
		{"fchown,fchownat"},
		{"setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr"},
	}
	tables := []string{"b64"}

	if arch == "amd64" {
		syscalls[0] = []string{"chmod,fchmod,fchmodat"}
		syscalls[1] = []string{"chown,fchown,fchownat,lchown"}
		tables = append(tables, "b32")
	}

	var rules [][]string
	for _, table := range tables {
		for _, s := range syscalls {
			rules = append(rules, []string{"-a", "always,exit", "-F", "arch=" + table, "-S", s[0], "-F", "auid>=1000", "-F", "auid!=-1", "-k", permKey})
		}
	}
	for _, f := range []string{"/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d"} {
		rules = append(rules, []string{"-w", f, "-p", "wa", "-k", permKey})
	}

	return rules
}

// Config says where auditctl and the shared path list are.
type Config struct {
	Auditctl    string
	SharedPaths string
}

// Collect loads the four watches (read, write, execute,
// attribute change) of each audit_watches path of the shared
// oscompliance.json that are not loaded yet, then emits the
// audit_watch_snapshot. It never removes a rule: what the administrator
// loaded stays.
func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	paths, _, err := wazuh.ReadSharedPaths(cfg.SharedPaths)
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
	status, err := host.Run(cfg.Auditctl, "-s")
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

	// The fixed permission rules: loaded as a set when none is.
	perm, err := loadedPermRules(cfg.Auditctl)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}
	// The fixed permission rules: loaded as a set when any is missing. A
	// rule already present makes auditctl fail with "exists": it counts.
	rules := permRules(runtime.GOARCH)
	if perm < len(rules) {
		perm = 0
		for _, rule := range rules {
			if _, err := host.Run(cfg.Auditctl, rule...); err != nil && !strings.Contains(err.Error(), "exist") {
				snapshot.Failed = append(snapshot.Failed, strings.Join(rule, " ")+": "+err.Error())
				continue
			}
			perm++
		}
	}

	// Only the whole set proves silence: a missing rule hides its changes.
	if perm >= len(rules) {
		snapshot.PermRules = perm
	}

	for _, p := range paths.AuditWatches {

		if why := unsafeWatch(p); why != "" {
			snapshot.Failed = append(snapshot.Failed, p+": "+why)
			continue
		}

		ok := true
		for _, w := range Keys {
			if slices.Contains(loaded, p+" "+w.Key) {
				continue
			}
			if _, err := host.Run(cfg.Auditctl, "-w", p, "-p", w.Perm, "-k", w.Key); err != nil {
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

		if why := unsafeWatch(b); why != "" {
			snapshot.Failed = append(snapshot.Failed, b+": "+why)
			continue
		}

		if !slices.Contains(loaded, b+" "+execKey) {
			if _, err := host.Run(cfg.Auditctl, "-w", b, "-p", "x", "-k", execKey); err != nil {
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

	out, err := host.Run(auditctl, "-l")
	if err != nil {
		return nil, err
	}

	return parseWatches(out), nil
}

func parseWatches(listing string) []string {

	var out []string

	for _, line := range strings.Split(listing, "\n") {

		f := strings.Fields(line)

		for _, w := range Keys {

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

// loadedPermRules counts the loaded rules with the permission key.
func loadedPermRules(auditctl string) (int, error) {

	out, err := host.Run(auditctl, "-l")
	if err != nil {
		return 0, err
	}

	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if slices.Contains(f, "key="+permKey) || (slices.Contains(f, "-k") && len(f) > 0 && f[len(f)-1] == permKey) {
			n++
		}
	}

	return n, nil
}

// broadPaths would flood the audit log: P-06 forbids them as resources.
var broadPaths = map[string]bool{"/": true, "/etc": true, "/usr": true, "/var": true, "/var/log": true, "/proc": true, "/sys": true, "/dev": true, "/bin": true, "/sbin": true, "/lib": true, "/boot": true, "/home": true, "/tmp": true}

// unsafeWatch says why a path from the manager is not watched, "" when it
// can be: absolute, clean, no blanks, and not a whole system tree.
func unsafeWatch(p string) string {
	switch {
	case !filepath.IsAbs(p) || filepath.Clean(p) != p:
		return "not an absolute, clean path"
	case strings.ContainsAny(p, " \t\n\r"):
		return "contains blanks"
	case broadPaths[p]:
		return "a whole system tree: watching it would flood the audit log"
	}
	return ""
}

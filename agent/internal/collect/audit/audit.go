package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

var Keys = []struct{ Perm, Key string }{
	{"r", "oscompliance_read"},
	{"w", "oscompliance_write"},
	{"x", "oscompliance_exec"},
	{"a", "oscompliance_attr"},
}

const execKey = "oscompliance_exec"

const permKey = "oscompliance_perm"

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

type Config struct {
	Auditctl string
	Wazuh    wazuh.AgentConfigPaths
}

func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	paths, _, err := wazuh.ReadSharedPaths(cfg.Wazuh)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, cfg.Wazuh.SharedConf+": "+err.Error()
		return e.Emit(snapshot)
	}
	snapshot.Wanted = append(snapshot.Wanted, paths.AuditWatches...)
	snapshot.ExecWanted = append(snapshot.ExecWanted, paths.ExecWatches...)

	if _, err := os.Stat(cfg.Auditctl); errors.Is(err, fs.ErrNotExist) {
		snapshot.Auditd = fact.AuditdAbsent
		return e.Emit(snapshot)
	}

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

	perm, err := loadedPermRules(cfg.Auditctl)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}

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

var broadPaths = map[string]bool{"/": true, "/etc": true, "/usr": true, "/var": true, "/var/log": true, "/proc": true, "/sys": true, "/dev": true, "/bin": true, "/sbin": true, "/lib": true, "/boot": true, "/home": true, "/tmp": true}

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

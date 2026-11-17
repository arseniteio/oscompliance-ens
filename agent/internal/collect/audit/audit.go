package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type watch struct{ Perm, Key string }

var (
	readWatch  = watch{"r", "oscompliance_read"}
	writeWatch = watch{"w", "oscompliance_write"}
	execWatch  = watch{"x", "oscompliance_exec"}
	attrWatch  = watch{"a", "oscompliance_attr"}
)

var (
	allWatches    = []watch{readWatch, writeWatch, execWatch, attrWatch}
	changeWatches = []watch{writeWatch, attrWatch}
)

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
	Throttle string
}

func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	paths, configured, err := wazuh.ReadSharedPaths(cfg.Wazuh)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, cfg.Wazuh.SharedConf+": "+err.Error()
		return e.Emit(snapshot)
	}
	snapshot.Wanted = append(snapshot.Wanted, paths.AuditWatches...)
	snapshot.Wanted = append(snapshot.Wanted, paths.ReadWatches...)
	snapshot.ReadWanted = append(snapshot.ReadWanted, paths.ReadWatches...)
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

	rules, err := loadedRules(cfg.Auditctl)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}
	loaded := watchesOf(slices.DeleteFunc(slices.Clone(rules), loadedRule.unfiltered))

	suspended, err := LoadThrottle(cfg.Throttle)
	if err != nil {
		snapshot.Failed = append(snapshot.Failed, cfg.Throttle+": "+err.Error())
	}
	suspended = suspended.Active(time.Now())

	perm, err := loadedPermRules(cfg.Auditctl)
	if err != nil {
		snapshot.Auditd, snapshot.Error = fact.AuditdError, err.Error()
		return e.Emit(snapshot)
	}

	wantedPerm := permRules(runtime.GOARCH)
	if perm < len(wantedPerm) {
		perm = 0
		for _, rule := range wantedPerm {
			if _, err := host.Run(cfg.Auditctl, rule...); err != nil && !strings.Contains(err.Error(), "exist") {
				snapshot.Failed = append(snapshot.Failed, strings.Join(rule, " ")+": "+err.Error())
				continue
			}
			perm++
		}
	}

	if perm >= len(wantedPerm) {
		snapshot.PermRules = perm
	}

	for _, p := range paths.AuditWatches {
		loadPathWatches(&snapshot, cfg.Auditctl, loaded, p, changeWatches, suspended)
	}
	for _, p := range paths.ReadWatches {
		loadPathWatches(&snapshot, cfg.Auditctl, loaded, p, allWatches, suspended)
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

	// Without the engine's block nothing says which watches are stale: keep them all.
	if !configured {
		return e.Emit(snapshot)
	}
	for _, r := range staleRules(rules, paths, suspended) {
		if _, err := host.Run(cfg.Auditctl, r.deletion()...); err != nil {
			snapshot.Failed = append(snapshot.Failed, r.Path+" "+r.Key+": not unloaded: "+err.Error())
			continue
		}
		snapshot.Unloaded = append(snapshot.Unloaded, r.Path+" "+r.Key)
	}

	return e.Emit(snapshot)
}

func loadPathWatches(snapshot *fact.AuditWatchSnapshot, auditctl string, loaded []string, path string, watches []watch, suspended Throttle) {

	if why := unsafeWatch(path); why != "" {
		snapshot.Failed = append(snapshot.Failed, path+": "+why)
		return
	}

	ok := true
	for _, w := range watches {
		if slices.Contains(loaded, path+" "+w.Key) {
			continue
		}
		if w == readWatch {
			if until, found := suspended[path]; found {
				snapshot.Failed = append(snapshot.Failed, path+" r: suspended until "+until.UTC().Format(time.RFC3339)+", its reads went over the volume limit")
				ok = false
				continue
			}
			if hot := hotReadPath(path); hot != "" {
				snapshot.Failed = append(snapshot.Failed, path+" r: every process reads "+hot+", a read watch would fill the disk")
				ok = false
				continue
			}
		}
		if _, err := host.Run(auditctl, watchRule(path, w, isDir(path))...); err != nil {
			snapshot.Failed = append(snapshot.Failed, path+" "+w.Perm+": "+err.Error())
			ok = false
		}
	}

	if ok {
		snapshot.Loaded = append(snapshot.Loaded, path)
	}
}

func watchRule(path string, w watch, dir bool) []string {

	if w != readWatch {
		return []string{"-w", path, "-p", w.Perm, "-k", w.Key}
	}

	// Daemons and NSS lookups read watched files constantly, and a read without
	// a login UID names no person, so it is no evidence for the controls that judge reads.
	field := "path=" + path
	if dir {
		field = "dir=" + path
	}
	return []string{"-a", "always,exit", "-F", field, "-F", "perm=r", "-F", "auid!=-1", "-k", w.Key}
}

func hotReadPath(path string) string {
	for _, hot := range catalog.HotReadPaths {
		if path == hot || strings.HasPrefix(path, hot+"/") || strings.HasPrefix(hot, path+"/") {
			return hot
		}
	}
	return ""
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
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

type loadedRule struct {
	Path    string
	Key     string
	Syscall bool
	Dir     bool
}

func loadedRules(auditctl string) ([]loadedRule, error) {

	out, err := host.Run(auditctl, "-l")
	if err != nil {
		return nil, err
	}

	return parseRules(out), nil
}

func parseWatches(listing string) []string {
	return watchesOf(parseRules(listing))
}

func watchesOf(rules []loadedRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Path+" "+r.Key)
	}
	return out
}

func parseRules(listing string) []loadedRule {

	var out []loadedRule

	for _, line := range strings.Split(listing, "\n") {

		f := strings.Fields(line)

		for _, w := range allWatches {

			if len(f) >= 2 && f[0] == "-w" && slices.Contains(f, "-k") && f[len(f)-1] == w.Key {
				out = append(out, loadedRule{Path: f[1], Key: w.Key})
				continue
			}

			if !slices.Contains(f, "key="+w.Key) {
				continue
			}
			for _, field := range f {
				if v, ok := strings.CutPrefix(field, "dir="); ok {
					out = append(out, loadedRule{Path: v, Key: w.Key, Syscall: true, Dir: true})
				} else if v, ok := strings.CutPrefix(field, "path="); ok {
					out = append(out, loadedRule{Path: v, Key: w.Key, Syscall: true})
				}
			}
		}
	}

	return out
}

func (r loadedRule) deletion() []string {

	perm := permOf(r.Key)
	if !r.Syscall {
		return []string{"-W", r.Path, "-p", perm, "-k", r.Key}
	}

	field := "path=" + r.Path
	if r.Dir {
		field = "dir=" + r.Path
	}
	rule := []string{"-d", "always,exit", "-F", field, "-F", "perm=" + perm}
	if r.Key == readWatch.Key {
		rule = append(rule, "-F", "auid!=-1")
	}
	return append(rule, "-k", r.Key)
}

// A read watch loaded with -w predates the auid filter: it fires for every daemon read.
func (r loadedRule) unfiltered() bool {
	return r.Key == readWatch.Key && !r.Syscall
}

func permOf(key string) string {
	for _, w := range allWatches {
		if w.Key == key {
			return w.Perm
		}
	}
	return ""
}

// The exec key is shared by the execution watch of read_watches paths and by exec_watches
// binaries, and the write and attribute keys by audit_watches and read_watches.
func staleRules(rules []loadedRule, paths wazuh.SharedPaths, suspended Throttle) []loadedRule {

	wanted := map[string][]string{
		readWatch.Key:  slices.DeleteFunc(slices.Clone(paths.ReadWatches), func(p string) bool { _, s := suspended[p]; return s }),
		writeWatch.Key: append(slices.Clone(paths.AuditWatches), paths.ReadWatches...),
		attrWatch.Key:  append(slices.Clone(paths.AuditWatches), paths.ReadWatches...),
		execWatch.Key:  append(slices.Clone(paths.ReadWatches), paths.ExecWatches...),
	}

	var stale []loadedRule
	for _, r := range rules {
		if r.unfiltered() || !slices.Contains(wanted[r.Key], r.Path) {
			stale = append(stale, r)
		}
	}
	return stale
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

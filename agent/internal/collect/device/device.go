// Package device reports how the machine protects an unattended session, its disk and its name resolution:
// its chassis, the screen lock the system dconf databases set for the graphical session, the idle timeouts of
// shells and logind, whether the root filesystem sits on dm-crypt, the DNS servers it asks, and its load.
package device

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

// Config holds the root every path is read under: / on a machine, a directory in tests.
type Config struct {
	Root string
}

var Default = Config{Root: "/"}

// Chassis types of SMBIOS that are carried around: portable, laptop, notebook, hand held, sub notebook,
// tablet, convertible, detachable.
var portable = []int{8, 9, 10, 11, 14, 30, 31, 32}

var displayManagers = []string{"/etc/systemd/system/display-manager.service", "/usr/sbin/gdm3", "/usr/sbin/gdm", "/usr/sbin/lightdm", "/usr/bin/sddm"}

func Collect(e *emit.Emitter, cfg Config) error {

	at := func(p string) string { return filepath.Join(cfg.Root, p) }
	s := fact.DeviceSecurity{Envelope: e.Envelope(fact.DeviceSecurityFact), Status: fact.SourceRead}

	if raw, err := fsread.ReadFile(at("/sys/class/dmi/id/chassis_type")); err == nil {
		s.ChassisType, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
		s.Portable = slices.Contains(portable, s.ChassisType)
	}
	s.Graphical = slices.ContainsFunc(displayManagers, func(p string) bool { _, err := os.Lstat(at(p)); return err == nil })

	s.IdleDelay, s.LockEnabled, s.LockDelay = screenLock(glob(at("/etc/dconf/db/*.d/*")))
	s.ShellTimeout, s.ShellReadonly = shellTimeout(append([]string{at("/etc/profile"), at("/etc/bash.bashrc")}, glob(at("/etc/profile.d/*.sh"))...))
	s.LogindIdle = logindIdle(append([]string{at("/etc/systemd/logind.conf")}, glob(at("/etc/systemd/logind.conf.d/*.conf"))...))
	s.RootDevice, s.RootEncrypted = rootEncryption(cfg.Root)
	s.Resolvers = resolvers(at("/etc/resolv.conf"), at("/run/systemd/resolve/resolv.conf"))
	s.CPUs, s.LoadPercent = load(at("/proc/loadavg"), at("/proc/cpuinfo"))
	s.MemoryPercent = memory(at("/proc/meminfo"))
	if raw, err := fsread.ReadFile(at("/proc/sys/net/ipv4/tcp_syncookies")); err == nil {
		s.SynCookies = strings.TrimSpace(string(raw)) != "0"
	}

	return e.Emit(s)
}

func glob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	slices.Sort(m)
	return m
}

func lines(path string) []string {
	raw, err := fsread.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		out = append(out, strings.TrimSpace(sc.Text()))
	}
	return out
}

// screenLock reads GNOME's keys in the system dconf keyfiles; a later file overrides an earlier one, as dconf
// compiles them.
func screenLock(files []string) (idle *int, enabled *bool, delay *int) {
	for _, f := range files {
		if strings.Contains(f, "/locks/") {
			continue
		}
		section := ""
		for _, l := range lines(f) {
			if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
				section = strings.Trim(l, "[]/")
				continue
			}
			key, value, ok := strings.Cut(l, "=")
			if !ok {
				continue
			}
			key, value = strings.TrimSpace(key), strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "uint32")), "'\"")
			switch section + "/" + key {
			case "org/gnome/desktop/session/idle-delay":
				if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
					idle = &n
				}
			case "org/gnome/desktop/screensaver/lock-enabled":
				b := strings.TrimSpace(value) == "true"
				enabled = &b
			case "org/gnome/desktop/screensaver/lock-delay":
				if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
					delay = &n
				}
			}
		}
	}
	return idle, enabled, delay
}

var tmout = regexp.MustCompile(`^(?:(?:export|readonly|declare\s+-\w+|typeset\s+-\w+)\s+)*TMOUT=["']?(\d+)`)

var readonlyTmout = regexp.MustCompile(`^(?:readonly|declare\s+-\w*r\w*|typeset\s+-\w*r\w*)\s+(?:\w+=\S*\s+)*TMOUT\b`)

// shellTimeout is the shortest TMOUT the login shells set, and whether a user can undo it.
func shellTimeout(files []string) (seconds int, readonly bool) {
	for _, f := range files {
		for _, l := range lines(f) {
			if m := tmout.FindStringSubmatch(l); m != nil {
				if n, _ := strconv.Atoi(m[1]); n > 0 && (seconds == 0 || n < seconds) {
					seconds = n
				}
			}
			readonly = readonly || readonlyTmout.MatchString(l)
		}
	}
	return seconds, readonly
}

// logindIdle is StopIdleSessionSec, the last file that sets it winning.
func logindIdle(files []string) int {
	seconds := 0
	for _, f := range files {
		for _, l := range lines(f) {
			if v, ok := strings.CutPrefix(l, "StopIdleSessionSec="); ok {
				seconds = duration(v)
			}
		}
	}
	return seconds
}

// duration reads a systemd time span such as 900, 15min or 1h; infinity is no limit.
func duration(v string) int {
	v = strings.TrimSpace(v)
	units := []struct {
		suffix string
		factor int
	}{{"min", 60}, {"h", 3600}, {"s", 1}, {"m", 60}}
	for _, u := range units {
		if n, ok := strings.CutSuffix(v, u.suffix); ok {
			if x, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return x * u.factor
			}
		}
	}
	n, _ := strconv.Atoi(v)
	return n
}

// rootEncryption finds the device mounted on / and whether it, or any device under it, is dm-crypt.
func rootEncryption(root string) (string, bool) {

	var device string
	for _, l := range lines(filepath.Join(root, "/proc/self/mounts")) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == "/" {
			device = f[0]
		}
	}
	if !strings.HasPrefix(device, "/dev/") {
		return device, false
	}
	if real, err := filepath.EvalSymlinks(filepath.Join(root, device)); err == nil {
		device = "/dev/" + filepath.Base(real)
	}
	name := filepath.Base(device)
	return name, crypt(root, name, 0)
}

func crypt(root, name string, depth int) bool {
	if depth > 8 {
		return false
	}
	block := filepath.Join(root, "/sys/class/block", name)
	if uuid, err := fsread.ReadFile(filepath.Join(block, "dm/uuid")); err == nil && strings.HasPrefix(string(uuid), "CRYPT-") {
		return true
	}
	slaves, _ := os.ReadDir(filepath.Join(block, "slaves"))
	return slices.ContainsFunc(slaves, func(s os.DirEntry) bool { return crypt(root, s.Name(), depth+1) })
}

// stub is the local resolver of systemd-resolved, which forwards to the servers of its own resolv.conf.
const stub = "127.0.0.53"

func resolvers(conf, upstream string) []string {
	out := nameservers(conf)
	if slices.Contains(out, stub) {
		out = append(slices.DeleteFunc(out, func(s string) bool { return s == stub }), nameservers(upstream)...)
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func nameservers(path string) []string {
	var out []string
	for _, l := range lines(path) {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" && !slices.Contains(out, f[1]) {
			out = append(out, f[1])
		}
	}
	return out
}

// tens rounds a percentage down to tens: the load changes every pass, the fact only when a step is crossed.
func tens(p float64) int { return int(p/10) * 10 }

func load(loadavg, cpuinfo string) (cpus, percent int) {
	for _, l := range lines(cpuinfo) {
		if strings.HasPrefix(l, "processor") {
			cpus++
		}
	}
	f := strings.Fields(strings.Join(lines(loadavg), " "))
	if cpus == 0 || len(f) < 3 {
		return cpus, 0
	}
	avg, _ := strconv.ParseFloat(f[2], 64)
	return cpus, tens(avg / float64(cpus) * 100)
}

func memory(meminfo string) int {
	values := map[string]float64{}
	for _, l := range lines(meminfo) {
		if f := strings.Fields(l); len(f) >= 2 {
			values[strings.TrimSuffix(f[0], ":")], _ = strconv.ParseFloat(f[1], 64)
		}
	}
	if values["MemTotal"] == 0 {
		return 0
	}
	return tens((values["MemTotal"] - values["MemAvailable"]) / values["MemTotal"] * 100)
}

// Command oscompliance-agent runs one collection pass and appends the facts to
// an NDJSON file read by the Wazuh agent.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/accounts"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/acl"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/audit"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/authprobe"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/firewall"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/listening"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/pam"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/settings"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/sudoers"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/sweep"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/umask"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oscompliance-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	output := flag.String("output", "/var/log/oscompliance/facts.ndjson", "NDJSON file the facts are appended to")
	host := flag.String("host", "", "host name to report (default: os.Hostname)")
	passwd := flag.String("passwd", "/etc/passwd", "account database read by EV-02 (EV-01, EV-04, EV-07 and EV-08 judge the same table)")
	shadow := flag.String("shadow", "/etc/shadow", "shadow file read by EV-02")
	group := flag.String("group", "/etc/group", "group file read by EV-06")
	sshd := flag.String("sshd", "/usr/sbin/sshd", "sshd binary asked for its effective configuration")
	sudoersPath := flag.String("sudoers", "/etc/sudoers", "main sudoers file; its includes are followed")
	pamDir := flag.String("pam-dir", "/etc/pam.d", "PAM configuration directory")
	collect := flag.String("collect", defaultCollectors, "comma-separated collectors to run: "+strings.Join(allCollectors, ", ")+"; the sweep is heavy and meant for a daily run")
	sweepTimeout := flag.Duration("sweep-timeout", 15*time.Minute, "time limit of the filesystem sweep")
	statePath := flag.String("state", "/var/lib/oscompliance/state.json", "what was last emitted in full, per collector")
	full := flag.Bool("full", false, "emit every record even when nothing changed")
	flag.Parse()

	selected := map[string]bool{}
	for _, name := range strings.Split(*collect, ",") {
		name = strings.TrimSpace(name)
		if !slices.Contains(allCollectors, name) {
			return fmt.Errorf("unknown collector %q (known: %s)", name, strings.Join(allCollectors, ", "))
		}
		selected[name] = true
	}

	if *host == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("hostname: %w", err)
		}
		*host = h
	}

	// One pass at a time: a pass that hangs must not pile up root processes
	// under cron, and it ends itself after maxPass.
	unlock, err := lockPass(filepath.Join(filepath.Dir(*statePath), "agent.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	watchdog := time.AfterFunc(maxPass, func() {
		fmt.Fprintln(os.Stderr, "oscompliance-agent: pass longer than", maxPass, "- stopped")
		os.Exit(2)
	})
	defer watchdog.Stop()

	runID, err := fact.NewRunID()
	if err != nil {
		return fmt.Errorf("run id: %w", err)
	}

	f, err := emit.OpenFile(*output)
	if err != nil {
		return err
	}
	defer f.Close()

	// Each collector writes to a buffer first: unchanged records are left
	// out before anything reaches the file (emit.State).
	var buf bytes.Buffer
	e := emit.New(&buf, *host, version, runID)
	state := emit.LoadState(*statePath)

	collectors := map[string]func() error{
		"identity": func() error {
			return accounts.CollectIdentity(e, accounts.IdentityConfig{
				PasswdPath: *passwd, ShadowPath: *shadow, SSHDPath: *sshd,
				LoginRecords: accounts.DefaultLoginRecords, LastlogPath: accounts.DefaultLastlog,
			})
		},
		"groups": func() error { return accounts.CollectGroups(e, accounts.GroupsConfig{GroupPath: *group}) },
		"umask": func() error {
			return umask.Collect(e, umask.Config{Files: umask.DefaultFiles, ProfileDir: "/etc/profile.d"})
		},
		"sudoers": func() error { return sudoers.Collect(e, sudoers.Config{Path: *sudoersPath}) },
		"config": func() error {
			return settings.Collect(e, settings.Config{Files: settings.DefaultFiles, SSHD: *sshd})
		},
		"authprobe": func() error { return authprobe.Collect(e) },
		"firewall":  func() error { return firewall.Collect(e, firewall.Default) },
		"wazuh":     func() error { return wazuh.CollectAgentConfig(e, wazuh.DefaultAgentConfig) },
		"acl":       func() error { return acl.Collect(e, acl.Config{SharedPaths: wazuh.DefaultSharedPaths}) },
		"audit": func() error {
			return audit.Collect(e, audit.Config{Auditctl: "/usr/sbin/auditctl", SharedPaths: wazuh.DefaultSharedPaths})
		},
		"services": func() error {
			return wazuh.CollectServiceLogs(e, wazuh.ServiceLogConfig{SharedConf: "/var/ossec/etc/shared/agent.conf", ClientKeys: "/var/ossec/etc/client.keys"})
		},
		"listening": func() error {
			return listening.Collect(e, listening.Config{Proc: "/proc", Systemctl: "/usr/bin/systemctl"})
		},
		"pam": func() error {
			return pam.Collect(e, pam.Config{Dir: *pamDir, Services: pam.DefaultServices, Types: pam.DefaultTypes})
		},
		"sweep": func() error {
			return sweep.Collect(e, sweep.Config{
				MountsPath: "/proc/self/mounts", Prune: sweep.DefaultPrune,
				PasswdPath: *passwd, GroupPath: *group,
				Timeout: *sweepTimeout, MaxRecords: 20000,
			})
		},
	}

	// Every collector runs even when an earlier one fails: one broken
	// evidence must not silence the others.
	var errs []error
	var inForce []string
	for _, name := range allCollectors {
		if selected[name] {
			collect, ok := collectors[name]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: no collector", name))
				continue
			}
			buf.Reset()
			if err := collect(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
			quiet := !loud(name, buf.Bytes())
			if err := flush(f, state, name, buf.Bytes(), *full, quiet); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
			if s := state.InForce(name); quiet && s != "" {
				inForce = append(inForce, s)
			}
		}
	}

	// The pass ends with what holds of every quiet collector that ran.
	if len(inForce) > 0 {
		buf.Reset()
		if err := e.Emit(fact.AgentPass{Envelope: e.Envelope(fact.AgentPassFact), InForce: inForce}); err != nil {
			errs = append(errs, err)
		} else if _, err := f.Write(buf.Bytes()); err != nil {
			errs = append(errs, fmt.Errorf("agent_pass: %w", err))
		}
	}

	if err := state.Save(); err != nil {
		errs = append(errs, fmt.Errorf("state: %w", err))
	}

	return errors.Join(errs...)
}

// loud collectors send their snapshot every time they run: the probe, whose
// line must come back as an alert each pass; the daily sweep, which no
// hourly agent_pass names; and the services with logs, whose consecutive
// reads op.acc.5 EV-09 judges.
func loud(collector string, lines []byte) bool {
	switch collector {
	case "authprobe", "sweep":
		return true
	case "services":
		return bytes.Count(lines, []byte("\n")) > 1
	}
	return false
}

// flush writes what one collector emitted, leaving out what was already
// sent (emit.State.Reduce), in a single write.
func flush(f io.Writer, state *emit.State, collector string, lines []byte, full, quiet bool) error {

	if len(lines) == 0 {
		return nil
	}

	out, commit, err := state.Reduce(collector, lines, time.Now(), full, quiet)
	if err != nil {
		// Something unexpected in the lines: send them all.
		out, commit = lines, func() {}
	}

	if len(out) == 0 {
		return nil
	}
	if _, err := f.Write(out); err != nil {
		return err
	}

	commit()
	return nil
}

// maxPass bounds one pass, the daily sweep (15 minutes at most) included.
const maxPass = 50 * time.Minute

// lockPass takes an exclusive lock, failing at once when another pass holds
// it.
func lockPass(path string) (func(), error) {

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another pass is running (%s): %w", path, err)
	}

	return func() { f.Close() }, nil
}

// allCollectors in the order they run. The facts each one emits are in
// catalog/docs/contracts.
var allCollectors = []string{"identity", "groups", "umask", "sudoers", "config", "pam", "authprobe", "listening", "services", "wazuh", "acl", "audit", "firewall", "sweep"}

// defaultCollectors is the hourly run; the sweep has its own daily run.
const defaultCollectors = "identity,groups,umask,sudoers,config,pam,authprobe,listening,services,wazuh,acl,audit,firewall"

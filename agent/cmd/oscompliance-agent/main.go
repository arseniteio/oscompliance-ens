package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/accounts"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/acl"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/audit"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/authprobe"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/config"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/firewall"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/listening"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/pam"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/sudoers"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/sweep"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/umask"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

var version = "dev"

const maxPass = 50 * time.Minute

var allCollectors = []string{"identity", "groups", "umask", "sudoers", "config", "pam", "authprobe", "listening", "services", "wazuh", "acl", "audit", "firewall", "sweep"}

func main() {
	opts, err := parseOptions()
	if err == nil {
		err = runPass(opts)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "oscompliance-agent:", err)
		os.Exit(1)
	}
}

func runPass(opts options) error {

	unlock, err := lockPass(filepath.Join(filepath.Dir(opts.State), "agent.lock"))
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

	out, err := emit.OpenFile(opts.Output)
	if err != nil {
		return err
	}
	defer out.Close()

	var buf bytes.Buffer
	e := emit.New(&buf, opts.Host, version, runID)
	state := emit.LoadState(opts.State)

	inForce, errs := runCollectors(out, &buf, state, collectorsFor(e, opts), opts)

	if err := writeAgentPass(out, &buf, e, inForce); err != nil {
		errs = append(errs, fmt.Errorf("agent_pass: %w", err))
	}

	if err := state.Save(); err != nil {
		errs = append(errs, fmt.Errorf("state: %w", err))
	}

	return errors.Join(errs...)
}

func collectorsFor(e *emit.Emitter, opts options) map[string]func() error {

	wazuhPaths := wazuh.DefaultAgentConfig
	wazuhPaths.SharedConf = opts.Paths.WazuhSharedConf
	wazuhPaths.ClientKeys = opts.Paths.WazuhClientKeys

	return map[string]func() error{
		"identity": func() error {
			return accounts.CollectIdentity(e, accounts.IdentityConfig{
				PasswdPath: opts.Paths.Passwd, ShadowPath: opts.Paths.Shadow, SSHDPath: opts.Paths.SSHD,
				LoginRecords: accounts.DefaultLoginRecords, LastlogPath: accounts.DefaultLastlog,
			})
		},
		"groups": func() error { return accounts.CollectGroups(e, accounts.GroupsConfig{GroupPath: opts.Paths.Group}) },
		"umask": func() error {
			return umask.Collect(e, umask.Config{Files: umask.DefaultFiles, ProfileDir: "/etc/profile.d"})
		},
		"sudoers": func() error { return sudoers.Collect(e, sudoers.Config{Path: opts.Paths.Sudoers}) },
		"config": func() error {
			return config.Collect(e, config.Config{Files: config.DefaultFiles, SSHD: opts.Paths.SSHD})
		},
		"authprobe": func() error { return authprobe.Collect(e) },
		"firewall":  func() error { return firewall.Collect(e, firewall.Default) },
		"wazuh":     func() error { return wazuh.CollectAgentConfig(e, wazuhPaths) },
		"acl":       func() error { return acl.Collect(e, acl.Config{Wazuh: wazuhPaths}) },
		"audit": func() error {
			return audit.Collect(e, audit.Config{Auditctl: "/usr/sbin/auditctl", Wazuh: wazuhPaths})
		},
		"services": func() error {
			return wazuh.CollectServiceLogs(e, wazuh.ServiceLogConfig{SharedConf: wazuhPaths.SharedConf, ClientKeys: wazuhPaths.ClientKeys})
		},
		"listening": func() error {
			return listening.Collect(e, listening.Config{Proc: "/proc", Systemctl: "/usr/bin/systemctl"})
		},
		"pam": func() error {
			return pam.Collect(e, pam.Config{Dir: opts.Paths.PAMDir, Services: pam.DefaultServices, Types: pam.DefaultTypes})
		},
		"sweep": func() error {
			return sweep.Collect(e, sweep.Config{
				MountsPath: "/proc/self/mounts", Prune: sweep.DefaultPrune,
				PasswdPath: opts.Paths.Passwd, GroupPath: opts.Paths.Group,
				Timeout: opts.SweepTimeout.Duration, MaxRecords: 20000,
			})
		},
	}
}

func runCollectors(out io.Writer, buf *bytes.Buffer, state *emit.State, collectors map[string]func() error, opts options) (inForce []string, errs []error) {

	for _, name := range allCollectors {
		if !opts.selected[name] {
			continue
		}

		buf.Reset()
		if err := collectors[name](); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}

		quiet := !loud(name, buf.Bytes())
		if err := flush(out, state, name, buf.Bytes(), opts.full, quiet); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}

		if snapshot := state.InForce(name); quiet && snapshot != "" {
			inForce = append(inForce, snapshot)
		}
	}

	return inForce, errs
}

func loud(collector string, lines []byte) bool {
	switch collector {
	case "authprobe", "sweep":
		return true
	case "services":
		return bytes.Count(lines, []byte("\n")) > 1
	}
	return false
}

func flush(out io.Writer, state *emit.State, collector string, lines []byte, full, quiet bool) error {

	if len(lines) == 0 {
		return nil
	}

	reduced, commit, err := state.Reduce(collector, lines, time.Now(), full, quiet)
	if err != nil {
		reduced, commit = lines, func() {}
	}

	if len(reduced) == 0 {
		return nil
	}

	if _, err := out.Write(reduced); err != nil {
		return err
	}

	commit()
	return nil
}

func writeAgentPass(out io.Writer, buf *bytes.Buffer, e *emit.Emitter, inForce []string) error {

	if len(inForce) == 0 {
		return nil
	}

	buf.Reset()
	if err := e.Emit(fact.AgentPass{Envelope: e.Envelope(fact.AgentPassFact), InForce: inForce}); err != nil {
		return err
	}

	_, err := out.Write(buf.Bytes())
	return err
}

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

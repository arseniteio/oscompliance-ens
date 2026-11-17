//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/accounts"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/acl"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/audit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/authprobe"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/backups"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/config"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/device"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/firewall"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/keys"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/listening"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/malware"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/neighbours"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/packages"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/pam"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/snapshots"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/sudoers"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/sweep"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/timesync"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/transactions"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/umask"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/units"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/updates"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/virtualization"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
)

var allCollectors = []string{"identity", "groups", "umask", "sudoers", "config", "pam", "authprobe", "listening", "services", "wazuh", "acl", "audit", "firewall", "neighbours", "virtualization", "packages", "units", "backups", "updates", "transactions", "snapshots", "malware", "timesync", "keys", "device", "sweep"}

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
		"authprobe":  func() error { return authprobe.Collect(e) },
		"firewall":   func() error { return firewall.Collect(e, firewall.Default) },
		"neighbours": func() error { return neighbours.Collect(e, neighbours.Default) },
		"packages":   func() error { return packages.Collect(e, packages.Default) },
		"units":      func() error { return units.Collect(e, units.Default) },
		"backups":    func() error { return backups.Collect(e, backups.Config{Wazuh: wazuhPaths, Mounts: backups.Mountinfo}) },
		"updates":    func() error { return updates.Collect(e, updates.Default) },
		"transactions": func() error {
			return transactions.Collect(e, transactions.Default)
		},
		"snapshots": func() error { return snapshots.Collect(e, snapshots.Default) },
		"malware":   func() error { return malware.Collect(e, malware.Default) },
		"timesync":  func() error { return timesync.Collect(e, timesync.Default) },
		"device":    func() error { return device.Collect(e, device.Default) },
		"keys": func() error {
			cfg := keys.Default
			cfg.Wazuh = wazuhPaths
			return keys.Collect(e, cfg)
		},
		"virtualization": func() error {
			return virtualization.Collect(e, virtualization.Default)
		},
		"wazuh": func() error { return wazuh.CollectAgentConfig(e, wazuhPaths) },
		"acl":   func() error { return acl.Collect(e, acl.Config{Wazuh: wazuhPaths}) },
		"audit": func() error {
			return audit.Collect(e, audit.Config{Auditctl: auditctl, Wazuh: wazuhPaths, Throttle: auditThrottle(opts)})
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

const (
	auditctl = "/usr/sbin/auditctl"
	auditLog = "/var/log/audit/audit.log"
)

func auditThrottle(opts options) string {
	return filepath.Join(filepath.Dir(opts.State), "audit-throttle.json")
}

// Each suspension goes to the authentication log, which Wazuh reads: rule 119006 alerts on it.
func guardWithAlerts(opts options) error {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_WARNING, authprobe.ProbeTag)
	if err != nil {
		return errors.Join(fmt.Errorf("syslog: %w", err), runAuditGuard(opts, os.Stderr))
	}
	defer w.Close()
	return runAuditGuard(opts, w)
}

// Own lock: the guard must keep running while an hourly pass holds agent.lock.
func runAuditGuard(opts options, alert io.Writer) error {

	unlock, err := lockPass(filepath.Join(filepath.Dir(opts.State), "audit-guard.lock"))
	if err != nil {
		return err
	}
	defer unlock()

	suspended, err := audit.Guard(audit.GuardConfig{
		Auditctl: auditctl, Log: auditLog, Throttle: auditThrottle(opts),
		Limit: opts.AuditReadLimit, Window: audit.DefaultGuardWindow, Suspend: audit.DefaultGuardSuspend,
	}, time.Now())
	for _, s := range suspended {
		if _, werr := fmt.Fprintf(alert, "read watch suspended %s until %s: %d reads in %s\n", s.Path, s.Until.UTC().Format(time.RFC3339), s.Reads, audit.DefaultGuardWindow); werr != nil {
			return errors.Join(err, werr)
		}
	}
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

func rotateFacts(string) error { return nil }

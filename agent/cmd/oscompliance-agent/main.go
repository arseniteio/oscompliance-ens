// Command oscompliance-agent runs one collection pass and appends the facts to
// an NDJSON file read by the Wazuh agent.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/controls/ens/opacc2"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/sysconf"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
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
	sudoers := flag.String("sudoers", "/etc/sudoers", "main sudoers file; its includes are followed")
	pamDir := flag.String("pam-dir", "/etc/pam.d", "PAM configuration directory")
	collect := flag.String("collect", defaultCollectors, "comma-separated collectors to run: "+strings.Join(allCollectors, ", ")+"; the sweep is heavy and meant for a daily run")
	sweepTimeout := flag.Duration("sweep-timeout", 15*time.Minute, "time limit of the filesystem sweep")
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

	runID, err := fact.NewRunID()
	if err != nil {
		return fmt.Errorf("run id: %w", err)
	}

	f, err := emit.OpenFile(*output)
	if err != nil {
		return err
	}
	defer f.Close()

	e := emit.New(f, *host, version, runID)

	collectors := map[string]func() error{
		"identity": func() error {
			return opacc1.CollectEV02(e, opacc1.EV02Config{
				PasswdPath: *passwd, ShadowPath: *shadow, SSHDPath: *sshd,
				LoginRecords: opacc1.DefaultLoginRecords, LastlogPath: opacc1.DefaultLastlog,
			})
		},
		"groups": func() error { return opacc1.CollectEV06(e, opacc1.EV06Config{GroupPath: *group}) },
		"umask": func() error {
			return opacc2.CollectUmask(e, opacc2.UmaskConfig{Files: opacc2.DefaultUmaskFiles, ProfileDir: "/etc/profile.d"})
		},
		"sudoers": func() error { return opacc2.CollectSudoers(e, opacc2.SudoersConfig{Path: *sudoers}) },
		"config": func() error {
			return sysconf.CollectConfig(e, sysconf.ConfigConfig{Files: sysconf.DefaultConfigFiles, SSHD: *sshd})
		},
		"authprobe": func() error { return sysconf.CollectAuthProbe(e) },
		"firewall":  func() error { return sysconf.CollectFirewall(e, sysconf.DefaultFirewall) },
		"wazuh":     func() error { return sysconf.CollectWazuhConfig(e, sysconf.DefaultWazuhConfig) },
		"acl":       func() error { return sysconf.CollectACL(e, sysconf.ACLConfig{SharedPaths: sysconf.DefaultSharedPaths}) },
		"audit": func() error {
			return sysconf.CollectAuditWatches(e, sysconf.AuditConfig{Auditctl: "/usr/sbin/auditctl", SharedPaths: sysconf.DefaultSharedPaths})
		},
		"services": func() error {
			return sysconf.CollectServiceLogs(e, sysconf.ServiceLogConfig{SharedConf: "/var/ossec/etc/shared/agent.conf", ClientKeys: "/var/ossec/etc/client.keys"})
		},
		"listening": func() error {
			return sysconf.CollectListening(e, sysconf.ListenConfig{Proc: "/proc", Systemctl: "/usr/bin/systemctl"})
		},
		"pam": func() error {
			return sysconf.CollectPAM(e, sysconf.PAMConfig{Dir: *pamDir, Services: sysconf.DefaultPAMServices, Types: sysconf.DefaultPAMTypes})
		},
		"sweep": func() error {
			return opacc2.CollectSweep(e, opacc2.SweepConfig{
				MountsPath: "/proc/self/mounts", Prune: opacc2.DefaultPrune,
				PasswdPath: *passwd, GroupPath: *group,
				Timeout: *sweepTimeout, MaxRecords: 20000,
			})
		},
	}

	// Every collector runs even when an earlier one fails: one broken
	// evidence must not silence the others.
	var errs []error
	for _, name := range allCollectors {
		if selected[name] {
			collect, ok := collectors[name]
			if !ok {
				errs = append(errs, fmt.Errorf("%s: no collector", name))
				continue
			}
			if err := collect(); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
			}
		}
	}

	return errors.Join(errs...)
}

// allCollectors in the order they run. The facts each one emits are in
// catalog/docs/contracts.
var allCollectors = []string{"identity", "groups", "umask", "sudoers", "config", "pam", "authprobe", "listening", "services", "wazuh", "acl", "audit", "firewall", "sweep"}

// defaultCollectors is the hourly run; the sweep has its own daily run.
const defaultCollectors = "identity,groups,umask,sudoers,config,pam,authprobe,listening,services,wazuh,acl,audit,firewall"

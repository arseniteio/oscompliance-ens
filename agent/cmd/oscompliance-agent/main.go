// Command oscompliance-agent runs one collection pass and appends the facts to
// an NDJSON file read by the Wazuh agent.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
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
	sshd := flag.String("sshd", "/usr/sbin/sshd", "sshd binary asked for AuthorizedKeysFile (EV-02)")
	flag.Parse()

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

	// Every collector runs even when an earlier one fails: one broken
	// evidence must not silence the others.
	return errors.Join(
		opacc1.CollectEV02(e, opacc1.EV02Config{PasswdPath: *passwd, ShadowPath: *shadow, SSHDPath: *sshd}),
		opacc1.CollectEV06(e, opacc1.EV06Config{GroupPath: *group}),
	)
}

// Command oscompliance-agent runs one collection pass and appends the facts to
// an NDJSON file read by the Wazuh agent.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fact"
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
	passwd := flag.String("passwd", "/etc/passwd", "account database read by EV-01")
	uidMin := flag.Int("uid-min", 1000, "lowest UID reported by EV-01")
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
	return opacc1.CollectEV01(e, opacc1.EV01Config{PasswdPath: *passwd, UIDMin: *uidMin})
}

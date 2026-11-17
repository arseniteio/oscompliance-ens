package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

var version = "dev"

const maxPass = 50 * time.Minute

func main() {
	opts, err := parseOptions()
	switch {
	case err == nil && opts.guardAudit:
		err = guardWithAlerts(opts)
	case err == nil:
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

	if err := rotateFacts(opts.Output); err != nil {
		return fmt.Errorf("rotate %s: %w", opts.Output, err)
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

	if err := writeAgentPass(out, &buf, e, inForce, opts.WazuhGroup); err != nil {
		errs = append(errs, fmt.Errorf("agent_pass: %w", err))
	}

	if err := state.Save(); err != nil {
		errs = append(errs, fmt.Errorf("state: %w", err))
	}

	return errors.Join(errs...)
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

func writeAgentPass(out io.Writer, buf *bytes.Buffer, e *emit.Emitter, inForce []string, wazuhGroup string) error {

	if len(inForce) == 0 {
		return nil
	}

	buf.Reset()
	if err := e.Emit(fact.AgentPass{Envelope: e.Envelope(fact.AgentPassFact), InForce: inForce, RequestedGroup: wazuhGroup}); err != nil {
		return err
	}

	_, err := out.Write(buf.Bytes())
	return err
}

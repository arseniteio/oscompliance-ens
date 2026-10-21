// Package run is one evaluation pass: read facts, judge, write verdicts.
package run

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is where the facts come from (source.Source in production).
type Facts interface {
	Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
	LatestSnapshots(ctx context.Context, since time.Time) (map[string]fact.AccountInventorySnapshot, error)
	AccountRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.AccountRecord, error)
}

// Sink is where verdicts go (store.Verdicts in production).
type Sink interface {
	Write(ctx context.Context, v verdict.Verdict) error
}

// Config holds the engine-side parameters of a pass.
type Config struct {
	// Window: only facts newer than this count for a verdict.
	Window time.Duration
	// Lookback: agents with any fact this recent are judged, so an agent
	// that stopped sending gets NOT_EVALUABLE instead of disappearing.
	Lookback      time.Duration
	EngineVersion string
}

// Once judges every known agent and writes one verdict per agent and
// evidence. A failure on one agent does not stop the others; all failures are
// returned together.
func Once(ctx context.Context, facts Facts, sink Sink, cfg Config, now time.Time) (int, error) {

	windowStart := now.Add(-cfg.Window)
	lookbackStart := now.Add(-cfg.Lookback)

	agents, err := facts.Agents(ctx, lookbackStart)

	if err != nil {
		return 0, fmt.Errorf("agents: %w", err)
	}

	snapshots, err := facts.LatestSnapshots(ctx, windowStart)

	if err != nil {
		return 0, fmt.Errorf("snapshots: %w", err)
	}

	var errs []error
	written := 0

	for _, agent := range agents {

		in := opacc1.EV01Input{}

		if snapshot, ok := snapshots[agent.ID]; ok {
			in.Snapshot = &snapshot

			if snapshot.SourceStatus == fact.SourceRead {
				// Records are matched by run_id, not by the window: the
				// snapshot of a pass is emitted after its records.
				records, err := facts.AccountRecords(ctx, agent.ID, snapshot.RunID, lookbackStart)
				if err != nil {
					errs = append(errs, fmt.Errorf("agent %s: records: %w", agent.ID, err))
					continue
				}
				in.Records = records
			}
		}

		j := opacc1.JudgeEV01(in)

		v := verdict.Verdict{
			OSComplianceVerdict: verdict.SchemaVersion,
			Timestamp:           now.UTC().Format(time.RFC3339),
			Control:             "op.acc.1",
			Evidence:            "EV-01",
			Agent:               agent,
			Status:              j.Status,
			Cause:               j.Cause,
			Reason:              j.Reason,
			WindowStart:         windowStart.UTC().Format(time.RFC3339),
			WindowEnd:           now.UTC().Format(time.RFC3339),
			EngineVersion:       cfg.EngineVersion,
		}
		if in.Snapshot != nil {
			v.RunID = in.Snapshot.RunID
		}

		if err := sink.Write(ctx, v); err != nil {
			errs = append(errs, fmt.Errorf("agent %s: write: %w", agent.ID, err))
			continue
		}

		written++
	}

	return written, errors.Join(errs...)
}

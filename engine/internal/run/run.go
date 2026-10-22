// Package run is one evaluation pass: read facts, judge, write verdicts.
package run

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is where the facts come from (source.Source in production).
type Facts interface {
	Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
	LatestSnapshots(ctx context.Context, since time.Time) (map[string]fact.AccountInventorySnapshot, error)
	AccountRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.AccountRecord, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	SSHLogins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	AuthActivity(ctx context.Context, since time.Time) (map[string]time.Time, error)
}

// identityDepth bounds how many earlier passes are tried when looking for the
// previous complete identity pass.
const identityDepth = 10

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
// evidence. A failure on one agent or evidence does not stop the others; all
// failures are returned together.
func Once(ctx context.Context, facts Facts, policy params.Lister, sink Sink, cfg Config, now time.Time) (int, error) {

	windowStart := now.Add(-cfg.Window)
	lookbackStart := now.Add(-cfg.Lookback)

	agents, err := facts.Agents(ctx, lookbackStart)

	if err != nil {
		return 0, fmt.Errorf("agents: %w", err)
	}

	inventories, err := facts.LatestSnapshots(ctx, windowStart)

	if err != nil {
		return 0, fmt.Errorf("account snapshots: %w", err)
	}

	currentIdentities, err := facts.IdentitySnapshots(ctx, windowStart, 1)

	if err != nil {
		return 0, fmt.Errorf("identity snapshots: %w", err)
	}

	earlierIdentities, err := facts.IdentitySnapshots(ctx, lookbackStart, identityDepth)

	if err != nil {
		return 0, fmt.Errorf("identity snapshots: %w", err)
	}

	authActivity, err := facts.AuthActivity(ctx, lookbackStart)

	if err != nil {
		return 0, fmt.Errorf("authentication activity: %w", err)
	}

	var errs []error
	written := 0

	write := func(agent verdict.Agent, evidence string, j verdict.Judgement, runID string) {
		v := verdict.Verdict{
			OSComplianceVerdict: verdict.SchemaVersion,
			Timestamp:           now.UTC().Format(time.RFC3339),
			Control:             "op.acc.1",
			Evidence:            evidence,
			Agent:               agent,
			Status:              j.Status,
			Cause:               j.Cause,
			Reason:              j.Reason,
			RunID:               runID,
			WindowStart:         windowStart.UTC().Format(time.RFC3339),
			WindowEnd:           now.UTC().Format(time.RFC3339),
			EngineVersion:       cfg.EngineVersion,
		}
		if err := sink.Write(ctx, v); err != nil {
			errs = append(errs, fmt.Errorf("agent %s %s: write: %w", agent.ID, evidence, err))
			return
		}
		written++
	}

	for _, agent := range agents {

		ev01, err := inputEV01(ctx, facts, agent.ID, inventories, lookbackStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-01: %w", agent.ID, err))
		} else {
			runID := ""
			if ev01.Snapshot != nil {
				runID = ev01.Snapshot.RunID
			}
			write(agent, "EV-01", opacc1.JudgeEV01(ev01), runID)
		}

		ev02, err := inputEV02(ctx, facts, agent.ID, currentIdentities[agent.ID], earlierIdentities[agent.ID], lookbackStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-02: %w", agent.ID, err))
		} else {
			runID := ""
			if ev02.Current != nil {
				runID = ev02.Current.RunID
			}
			write(agent, "EV-02", opacc1.JudgeEV02(ev02), runID)
		}

		// EV-03 and EV-05 read the same logins against different lists.
		logins, err := facts.SSHLogins(ctx, agent.ID, windowStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s sshd logins: %w", agent.ID, err))
		} else {
			_, authSeen := authActivity[agent.ID]
			write(agent, "EV-03", opacc1.JudgeEV03(loginInput(policy, agent.ID, "P-04", authSeen, logins)), "")
			write(agent, "EV-05", opacc1.JudgeEV05(loginInput(policy, agent.ID, "P-03", authSeen, logins)), "")
		}
	}

	return written, errors.Join(errs...)
}

func inputEV01(ctx context.Context, facts Facts, agentID string, snapshots map[string]fact.AccountInventorySnapshot, since time.Time) (opacc1.EV01Input, error) {

	in := opacc1.EV01Input{}

	snapshot, ok := snapshots[agentID]
	if !ok {
		return in, nil
	}

	in.Snapshot = &snapshot

	if snapshot.SourceStatus != fact.SourceRead {
		return in, nil
	}

	// Records are matched by run_id, not by the window: the snapshot of a
	// pass is emitted after its records.
	records, err := facts.AccountRecords(ctx, agentID, snapshot.RunID, since)
	in.Records = records

	return in, err
}

// inputEV02 takes the newest pass in the window as current and the newest
// complete pass before it as previous. A pass counts as complete when both
// files were read and every announced record arrived.
func inputEV02(ctx context.Context, facts Facts, agentID string, current, earlier []fact.IdentitySnapshot, since time.Time) (opacc1.EV02Input, error) {

	in := opacc1.EV02Input{}

	if len(current) == 0 {
		return in, nil
	}

	in.Current = &current[0]

	if readBoth(*in.Current) {
		records, err := facts.IdentityRecords(ctx, agentID, in.Current.RunID, since)
		if err != nil {
			return in, err
		}
		in.Records = records
	}

	for i := range earlier {

		candidate := earlier[i]

		if candidate.RunID == in.Current.RunID || !readBoth(candidate) || candidate.RecordsEmitted == nil {
			continue
		}

		records, err := facts.IdentityRecords(ctx, agentID, candidate.RunID, since)
		if err != nil {
			return in, err
		}

		if len(records) >= *candidate.RecordsEmitted {
			in.Previous = &candidate
			in.PreviousRecords = records
			break
		}
	}

	return in, nil
}

func readBoth(s fact.IdentitySnapshot) bool {
	return s.PasswdStatus == fact.SourceRead && s.ShadowStatus == fact.SourceRead
}

func loginInput(policy params.Lister, agentID, paramID string, authSeen bool, logins []source.Login) opacc1.LoginInput {

	in := opacc1.LoginInput{AuthSeen: authSeen, Logins: logins}

	list, err := policy.List(agentID, "op.acc.1", paramID)
	if err != nil {
		in.ForbiddenProblem = err.Error()
	}
	in.Forbidden = list

	return in
}

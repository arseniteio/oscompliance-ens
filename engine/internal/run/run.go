// Package run is one evaluation pass: read facts, judge, write verdicts.
package run

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
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
	GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error)
	GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error)
}

// identityDepth bounds how many earlier passes are tried when looking for the
// previous complete identity pass.
const identityDepth = 10

// History is the per-account history EV-08 needs (store.History in
// production).
type History interface {
	Load(ctx context.Context, agentID string) (map[string]history.Account, error)
	Save(ctx context.Context, accounts []history.Account) error
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
// evidence. A failure on one agent or evidence does not stop the others; all
// failures are returned together.
func Once(ctx context.Context, facts Facts, policy params.Lister, hist History, sink Sink, cfg Config, now time.Time) (int, error) {

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

	groupSnapshots, err := facts.GroupSnapshots(ctx, windowStart)

	if err != nil {
		return 0, fmt.Errorf("group snapshots: %w", err)
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

			// EV-07 judges the same inventory against P-07 (column usuario).
			ev07 := opacc1.EV07Input{Inventory: ev01}
			authorized, err := policy.ListColumn(agent.ID, "op.acc.1", "P-07", 0)
			if err != nil {
				ev07.AuthorizedProblem = err.Error()
			}
			ev07.Authorized = authorized
			write(agent, "EV-07", opacc1.JudgeEV07(ev07), runID)
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

		// EV-03, EV-05 and EV-06 read the same logins.
		logins, err := facts.SSHLogins(ctx, agent.ID, windowStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s sshd logins: %w", agent.ID, err))
			continue
		}

		_, authSeen := authActivity[agent.ID]
		write(agent, "EV-03", opacc1.JudgeEV03(loginInput(policy, agent.ID, "P-04", authSeen, logins)), "")
		write(agent, "EV-05", opacc1.JudgeEV05(loginInput(policy, agent.ID, "P-03", authSeen, logins)), "")

		write(agent, "EV-04", opacc1.JudgeEV04(inputEV04(policy, agent.ID, ev02, now)), "")

		ev08, err := inputEV08(ctx, hist, policy, agent, ev02, windowStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-08: %w", agent.ID, err))
		} else {
			write(agent, "EV-08", opacc1.JudgeEV08(ev08), "")
		}

		ev06, err := inputEV06(ctx, facts, policy, agent.ID, groupSnapshots, ev02, lookbackStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-06: %w", agent.ID, err))
		} else {
			ev06.AuthSeen, ev06.Logins = authSeen, logins
			runID := ""
			if ev06.Groups != nil {
				runID = ev06.Groups.RunID
			}
			write(agent, "EV-06", opacc1.JudgeEV06(ev06), runID)
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

	matcher, err := policy.Matcher(agentID, "op.acc.1", paramID)
	if err != nil {
		in.ForbiddenProblem = err.Error()
	}
	in.Forbidden = matcher

	return in
}

// inputEV06 gathers the group pass, the account list of the EV-02 input
// (current pass when complete, otherwise the previous complete one) and P-11
// and P-12.
func inputEV06(ctx context.Context, facts Facts, policy params.Lister, agentID string, snapshots map[string]fact.GroupSnapshot, ev02 opacc1.EV02Input, since time.Time) (opacc1.EV06Input, error) {

	in := opacc1.EV06Input{}

	privileged, err := policy.List(agentID, "op.acc.1", "P-11")
	switch {
	case errors.Is(err, params.ErrNotSet):
		in.Privileged, in.PrivilegedDefault = opacc1.DefaultPrivilegedGroups, true
	case err != nil:
		in.ConfigProblem = "P-11: " + err.Error()
	default:
		in.Privileged = privileged
	}

	suffix, err := policy.List(agentID, "op.acc.1", "P-12")
	switch {
	case errors.Is(err, params.ErrNotSet):
		// No suffix: nobody is excluded.
	case err != nil:
		in.ConfigProblem = "P-12: " + err.Error()
	default:
		in.Suffix = suffix[0]
	}

	if records, problem := completeIdentity(ev02); problem != "" {
		in.AccountsProblem = problem
	} else {
		in.Accounts = identityNames(records)
	}

	snapshot, ok := snapshots[agentID]
	if !ok {
		return in, nil
	}

	in.Groups = &snapshot

	if snapshot.GroupStatus != fact.SourceRead {
		return in, nil
	}

	records, err := facts.GroupRecords(ctx, agentID, snapshot.RunID, since)
	in.GroupRecords = records

	return in, err
}

// completeIdentity returns the identity table of the EV-02 input: the current
// pass when complete, otherwise the previous complete one.
func completeIdentity(ev02 opacc1.EV02Input) ([]fact.IdentityRecord, string) {

	current := ev02.Current

	if current != nil && readBoth(*current) && current.RecordsEmitted != nil && len(ev02.Records) >= *current.RecordsEmitted {
		return ev02.Records, ""
	}

	if ev02.Previous != nil {
		return ev02.PreviousRecords, ""
	}

	return nil, "no complete identity pass (EV-02) in the lookback"
}

// inputEV04 gathers the identity table and P-05, P-09 and P-10.
func inputEV04(policy params.Lister, agentID string, ev02 opacc1.EV02Input, now time.Time) opacc1.EV04Input {

	in := opacc1.EV04Input{Now: now}

	in.Accounts, in.AccountsProblem = completeIdentity(ev02)

	off := offboardingParams(policy, agentID)
	in.Declared, in.DeclaredSet, in.UIDMin = off.declared, off.declaredSet, off.uidMin

	problems := off.problems

	deadline, err := policy.Number(agentID, "op.acc.1", "P-05")
	if err != nil {
		problems = append(problems, "P-05: "+err.Error())
	}
	in.DeadlineDays = int(deadline)

	in.ConfigProblem = strings.Join(problems, "; ")

	return in
}

// inputEV08 brings the agent's history up to date with its current complete
// identity pass, saves the changes, and returns the accounts deleted in the
// window with P-06, P-09 and P-10.
func inputEV08(ctx context.Context, hist History, policy params.Lister, agent verdict.Agent, ev02 opacc1.EV02Input, windowStart time.Time) (opacc1.EV08Input, error) {

	off := offboardingParams(policy, agent.ID)
	in := opacc1.EV08Input{Declared: off.declared, UIDMin: off.uidMin}

	problems := off.problems

	retention, err := policy.Number(agent.ID, "op.acc.1", "P-06")
	if err != nil {
		problems = append(problems, "P-06: "+err.Error())
	}
	in.RetentionDays = int(retention)
	in.ConfigProblem = strings.Join(problems, "; ")

	known, err := hist.Load(ctx, agent.ID)
	if err != nil {
		return in, fmt.Errorf("history: %w", err)
	}

	// Only the current pass moves the history forward: the previous one was
	// applied when it was current.
	current := ev02.Current
	complete := current != nil && readBoth(*current) && current.RecordsEmitted != nil && len(ev02.Records) >= *current.RecordsEmitted

	if !complete {
		in.IdentityProblem = "no complete current identity pass (EV-02) in the window"
	} else {
		at, err := time.Parse(time.RFC3339, current.TS)
		if err != nil {
			return in, fmt.Errorf("identity pass %s: ts: %w", current.RunID, err)
		}

		changed := history.Update(known, agent.ID, agent.Name, ev02.Records, at, current.RunID, opacc1.IsDisabled)

		if err := hist.Save(ctx, changed); err != nil {
			return in, fmt.Errorf("history: %w", err)
		}

		for _, account := range changed {
			known[account.AccountName] = account
		}
	}

	for _, account := range known {
		if account.DeletedAt != nil && !account.DeletedAt.Before(windowStart) {
			in.Deleted = append(in.Deleted, account)
		}
	}

	return in, nil
}

type offboarding struct {
	declared    map[string]time.Time
	declaredSet bool
	uidMin      int
	problems    []string
}

// offboardingParams reads P-09 and P-10, shared by EV-04 and EV-08.
func offboardingParams(policy params.Lister, agentID string) offboarding {

	off := offboarding{declared: map[string]time.Time{}, uidMin: opacc1.DefaultUIDMin}

	uidMin, err := policy.Number(agentID, "op.acc.1", "P-10")
	switch {
	case errors.Is(err, params.ErrNotSet):
		// Product default, as v1.
	case err != nil:
		off.problems = append(off.problems, "P-10: "+err.Error())
	default:
		off.uidMin = int(uidMin)
	}

	// P-09 rows are "usuario | fecha_baja"; a date that cannot be read is a
	// configuration error, not a row to skip.
	rows, err := policy.List(agentID, "op.acc.1", "P-09")
	switch {
	case errors.Is(err, params.ErrNotSet):
	case err != nil:
		off.problems = append(off.problems, "P-09: "+err.Error())
	default:
		for _, row := range rows {
			cells := strings.Split(row, "|")
			if len(cells) < 2 {
				off.problems = append(off.problems, fmt.Sprintf("P-09: row %q has no date", row))
				continue
			}
			name, date := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
			left, err := time.Parse("2006-01-02", date)
			if name == "" || err != nil {
				off.problems = append(off.problems, fmt.Sprintf("P-09: row %q is not \"usuario | YYYY-MM-DD\"", row))
				continue
			}
			off.declared[name] = left
			off.declaredSet = true
		}
	}

	return off
}

func identityNames(records []fact.IdentityRecord) []string {

	names := make([]string, 0, len(records))

	for _, record := range records {
		names = append(names, record.AccountName)
	}

	return names
}

package opacc1

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	AuthActivity(ctx context.Context, since time.Time) (map[string]time.Time, error)
	ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error)
	GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error)
	GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error)
}

type History interface {
	Load(ctx context.Context, agentID string) (map[string]history.Account, error)
	Save(ctx context.Context, accounts []history.Account) error
}

const identityDepth = 10

type Evaluator struct {
	facts Facts
	hist  History

	pass              evaluator.Pass
	currentIdentities map[string][]fact.IdentitySnapshot
	earlierIdentities map[string][]fact.IdentitySnapshot
	authActivity      map[string]time.Time
	groupSnapshots    map[string]fact.GroupSnapshot
}

func NewEvaluator(facts Facts, hist History) *Evaluator {
	return &Evaluator{facts: facts, hist: hist}
}

func (e *Evaluator) Control() string { return "op.acc.1" }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass

	var err error

	if e.currentIdentities, err = e.facts.IdentitySnapshots(ctx, pass.WindowStart, 1); err != nil {
		return fmt.Errorf("identity snapshots: %w", err)
	}

	if e.earlierIdentities, err = e.facts.IdentitySnapshots(ctx, pass.LookbackStart, identityDepth); err != nil {
		return fmt.Errorf("identity snapshots: %w", err)
	}

	if e.authActivity, err = e.facts.AuthActivity(ctx, pass.LookbackStart); err != nil {
		return fmt.Errorf("authentication activity: %w", err)
	}

	// The authentication probe proves the log reaches Wazuh, so a machine
	// nobody logged in to is judged on its empty log, not left unevaluable.
	probes, err := e.facts.ProbesSeen(ctx, pass.LookbackStart)
	if err != nil {
		return fmt.Errorf("authentication probes: %w", err)
	}
	if e.authActivity == nil {
		e.authActivity = map[string]time.Time{}
	}
	for agentID, runs := range probes {
		if _, seen := e.authActivity[agentID]; !seen && len(runs) > 0 {
			e.authActivity[agentID] = pass.LookbackStart
		}
	}

	if e.groupSnapshots, err = e.facts.GroupSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("group snapshots: %w", err)
	}

	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	facts, hist := e.facts, e.hist
	now, windowStart, lookbackStart := e.pass.Now, e.pass.WindowStart, e.pass.LookbackStart
	currentIdentities, earlierIdentities, authActivity, groupSnapshots := e.currentIdentities, e.earlierIdentities, e.authActivity, e.groupSnapshots

	results := map[string]evaluator.Result{}
	var errs []error

	write := func(evidence string, j verdict.Judgement, runID string) {
		results[evidence] = evaluator.Result{Judgement: j, RunID: runID}
	}

	ev02, err := inputEV02(ctx, facts, agent.ID, currentIdentities[agent.ID], earlierIdentities[agent.ID], lookbackStart)
	if err != nil {
		errs = append(errs, fmt.Errorf("agent %s identity passes: %w", agent.ID, err))
	} else {
		runID := ""
		if ev02.Current != nil {
			runID = ev02.Current.RecordsRun()
		}

		inventory := Inventory{Current: ev02.Current, Records: ev02.Records, Today: now.UTC().Truncate(24 * time.Hour)}
		inventory.UIDMin, inventory.UIDMinProblem = uidMinParam(policy, agent.ID)

		write("EV-01", JudgeEV01(inventory), runID)
		write("EV-02", JudgeEV02(ev02), runID)

		ev07 := EV07Input{Inventory: inventory}
		authorized, err := policy.ListColumn(agent.ID, "op.acc.1", "P-07", 0)
		if err != nil {
			ev07.AuthorizedProblem = passes.Param("P-07", err)
		}
		ev07.Authorized = authorized
		write("EV-07", JudgeEV07(ev07), runID)

		write("EV-04", JudgeEV04(inputEV04(policy, agent.ID, ev02, now)), "")

		ev08, err := inputEV08(ctx, hist, policy, agent, ev02, windowStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-08: %w", agent.ID, err))
		} else {
			write("EV-08", JudgeEV08(ev08), "")
		}
	}

	logins, err := facts.Logins(ctx, agent.ID, windowStart)
	if err != nil {
		errs = append(errs, fmt.Errorf("agent %s logins: %w", agent.ID, err))
	} else {
		_, authSeen := authActivity[agent.ID]
		write("EV-03", JudgeEV03(loginInput(policy, agent.ID, "P-04", authSeen, logins)), "")
		write("EV-05", JudgeEV05(loginInput(policy, agent.ID, "P-03", authSeen, logins)), "")

		ev06, err := inputEV06(ctx, facts, policy, agent.ID, groupSnapshots, ev02, lookbackStart)
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s EV-06: %w", agent.ID, err))
		} else {
			ev06.AuthSeen, ev06.Logins = authSeen, logins
			runID := ""
			if ev06.Groups != nil {
				runID = ev06.Groups.RecordsRun()
			}
			write("EV-06", JudgeEV06(ev06), runID)
		}
	}

	return results, errors.Join(errs...)
}

func inputEV02(ctx context.Context, facts Facts, agentID string, current, earlier []fact.IdentitySnapshot, since time.Time) (EV02Input, error) {

	in := EV02Input{}

	if len(current) == 0 {
		return in, nil
	}

	in.Current = &current[0]

	if readBoth(*in.Current) {
		records, err := facts.IdentityRecords(ctx, agentID, in.Current.RecordsRun(), since)
		if err != nil {
			return in, err
		}
		in.Records = records
	}

	for i := range earlier {

		candidate := earlier[i]

		if candidate.RecordsRun() == in.Current.RecordsRun() || !readBoth(candidate) || candidate.RecordsEmitted == nil {
			continue
		}

		records, err := facts.IdentityRecords(ctx, agentID, candidate.RecordsRun(), since)
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

func loginInput(policy params.Lister, agentID, paramID string, authSeen bool, logins []source.Login) LoginInput {

	in := LoginInput{AuthSeen: authSeen, Logins: logins}

	matcher, err := policy.Matcher(agentID, "op.acc.1", paramID)
	if err != nil {
		in.ForbiddenProblem = passes.Param(paramID, err)
	}
	in.Forbidden = matcher

	return in
}

func inputEV06(ctx context.Context, facts Facts, policy params.Lister, agentID string, snapshots map[string]fact.GroupSnapshot, ev02 EV02Input, since time.Time) (EV06Input, error) {

	in := EV06Input{}

	privileged, err := policy.List(agentID, "op.acc.1", "P-11")
	switch {
	case errors.Is(err, params.ErrNotSet):
		in.Privileged, in.PrivilegedDefault = DefaultPrivilegedGroups, true
	case err != nil:
		in.ConfigProblem = passes.Param("P-11", err)
	default:
		in.Privileged = privileged
	}

	affixRows, err := policy.List(agentID, "op.acc.1", adminAffixParam)
	switch {
	case errors.Is(err, params.ErrNotSet):

	case err != nil:
		in.ConfigProblem = passes.Param(adminAffixParam, err)
	default:
		var problem catalog.Message
		if in.AdminAffixes, problem = parseAdminAffixes(affixRows); !problem.IsZero() {
			in.ConfigProblem = problem
		}
	}

	if records, problem := completeIdentity(ev02); !problem.IsZero() {
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

	records, err := facts.GroupRecords(ctx, agentID, snapshot.RecordsRun(), since)
	in.GroupRecords = records

	return in, err
}

func completeIdentity(ev02 EV02Input) ([]fact.IdentityRecord, catalog.Message) {

	current := ev02.Current

	if current != nil && readBoth(*current) && current.RecordsEmitted != nil && len(ev02.Records) >= *current.RecordsEmitted {
		return ev02.Records, catalog.Message{}
	}

	if ev02.Previous != nil {
		return ev02.PreviousRecords, catalog.Message{}
	}

	return nil, catalog.Says("opacc1.no_identity_pass_lookback")
}

func inputEV04(policy params.Lister, agentID string, ev02 EV02Input, now time.Time) EV04Input {

	in := EV04Input{Now: now}

	in.Accounts, in.AccountsProblem = completeIdentity(ev02)

	off := offboardingParams(policy, agentID)
	in.Declared, in.DeclaredSet, in.UIDMin = off.declared, off.declaredSet, off.uidMin

	problems := off.problems

	deadline, err := policy.Number(agentID, "op.acc.1", "P-05")
	if err != nil {
		problems = append(problems, passes.Param("P-05", err))
	}
	in.DeadlineDays = int(deadline)

	in.ConfigProblem = passes.Problems(problems)

	return in
}

func inputEV08(ctx context.Context, hist History, policy params.Lister, agent verdict.Agent, ev02 EV02Input, windowStart time.Time) (EV08Input, error) {

	off := offboardingParams(policy, agent.ID)
	in := EV08Input{Declared: off.declared, UIDMin: off.uidMin}

	problems := off.problems

	retention, err := policy.Number(agent.ID, "op.acc.1", "P-06")
	if err != nil {
		problems = append(problems, passes.Param("P-06", err))
	}
	in.RetentionDays = int(retention)
	in.ConfigProblem = passes.Problems(problems)

	known, err := hist.Load(ctx, agent.ID)
	if err != nil {
		return in, fmt.Errorf("history: %w", err)
	}

	current := ev02.Current
	complete := current != nil && readBoth(*current) && current.RecordsEmitted != nil && len(ev02.Records) >= *current.RecordsEmitted

	if !complete {
		in.IdentityProblem = catalog.Says("opacc1.no_identity_pass_window")
	} else {
		at, err := time.Parse(time.RFC3339, current.TS)
		if err != nil {
			return in, fmt.Errorf("identity pass %s: ts: %w", current.RunID, err)
		}

		changed := history.Update(known, agent.ID, agent.Name, ev02.Records, at, current.RunID, IsDisabled)

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
	problems    []catalog.Message
}

func offboardingParams(policy params.Lister, agentID string) offboarding {

	off := offboarding{declared: map[string]time.Time{}}

	var problem catalog.Message
	if off.uidMin, problem = uidMinParam(policy, agentID); !problem.IsZero() {
		off.problems = append(off.problems, problem)
	}

	rows, err := policy.List(agentID, "op.acc.1", "P-09")
	switch {
	case errors.Is(err, params.ErrNotSet):
	case err != nil:
		off.problems = append(off.problems, passes.Param("P-09", err))
	default:
		for _, row := range rows {
			cells := strings.Split(row, "|")
			if len(cells) < 2 {
				off.problems = append(off.problems, catalog.Says("opacc1.p09_no_date", "row", row))
				continue
			}
			name, date := strings.TrimSpace(cells[0]), strings.TrimSpace(cells[1])
			left, err := time.Parse("2006-01-02", date)
			if name == "" || err != nil {
				off.problems = append(off.problems, catalog.Says("opacc1.p09_bad_row", "row", row))
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

func uidMinParam(policy params.Lister, agentID string) (int, catalog.Message) {

	uidMin, err := policy.Number(agentID, "op.acc.1", "P-10")

	switch {
	case errors.Is(err, params.ErrNotSet):
		return DefaultUIDMin, catalog.Message{}
	case err != nil:
		return DefaultUIDMin, passes.Param("P-10", err)
	case uidMin < 0 || uidMin != float64(int(uidMin)):
		return DefaultUIDMin, catalog.Says("opacc1.p10_not_uid", "value", uidMin)
	}

	return int(uidMin), catalog.Message{}
}

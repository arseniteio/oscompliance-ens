package opacc6

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is what op.acc.6 reads (source.Source in production).
type Facts interface {
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	PAMSnapshots(ctx context.Context, since time.Time) (map[string]fact.PAMSnapshot, error)
	PAMRules(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PAMRule, error)
	SudoersSnapshots(ctx context.Context, since time.Time) (map[string]fact.SudoersSnapshot, error)
	SudoGrants(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SudoGrant, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	Failures(ctx context.Context, agentID string, since time.Time) ([]source.Failure, error)
	Lockouts(ctx context.Context, agentID string, since time.Time) ([]source.Lockout, error)
	AuthLogProbes(ctx context.Context, since time.Time, n int) (map[string][]fact.AuthLogProbe, error)
	ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error)
}

// maxProbes is how many probes of the window are compared: an hourly agent
// writes 26 in the default window.
const maxProbes = 48

const control = "op.acc.6"

// Evaluator judges op.acc.6.
type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	identities map[string][]fact.IdentitySnapshot
	configs    map[string]fact.ConfigSnapshot
	pams       map[string]fact.PAMSnapshot
	sudoers    map[string]fact.SudoersSnapshot
	probes     map[string][]fact.AuthLogProbe
	seen       map[string]map[string]bool

	decisions map[string]map[string]verdict.Judgement
}

// NewEvaluator returns the op.acc.6 evaluator.
func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

// Control is the catalog id.
func (e *Evaluator) Control() string { return control }

// Begin reads the newest snapshot of every fact type, for every agent.
func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}
	var err error

	if e.identities, err = e.facts.IdentitySnapshots(ctx, pass.WindowStart, 1); err != nil {
		return fmt.Errorf("identity snapshots: %w", err)
	}
	if e.configs, err = e.facts.ConfigSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("config snapshots: %w", err)
	}
	if e.pams, err = e.facts.PAMSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("pam snapshots: %w", err)
	}
	if e.sudoers, err = e.facts.SudoersSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("sudoers snapshots: %w", err)
	}
	if e.probes, err = e.facts.AuthLogProbes(ctx, pass.WindowStart, maxProbes); err != nil {
		return fmt.Errorf("auth log probes: %w", err)
	}
	if e.seen, err = e.facts.ProbesSeen(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("probe alerts: %w", err)
	}

	return nil
}

// Decisions are the P-01 decisions taken in Agent.
func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

// Agent judges the evidences built so far: EV-01, EV-03, EV-04, EV-05, EV-07,
// EV-09, EV-10, EV-11 and EV-12. The others are missing from the result and
// count as COLLECTION gaps.
func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	results := map[string]evaluator.Result{}
	var errs []error
	since := e.pass.LookbackStart
	today := e.pass.Now

	e.decisions[agent.ID] = MechanismDecisions(Mechanism(policy.List(agent.ID, control, "P-01")))

	// The facts, each read once. A read that fails leaves out only the
	// evidences that need it.
	failed := map[string]bool{}
	read := func(name string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			failed[name] = true
		}
	}

	settings, err := e.settings(ctx, agent.ID, since)
	read("config", err)
	pam, err := e.pam(ctx, agent.ID, since)
	read("pam", err)
	accounts, err := e.accounts(ctx, agent.ID, since)
	read("identity", err)
	sudoers, err := e.sudoersOf(ctx, agent.ID, since)
	read("sudoers", err)
	logins, err := e.facts.Logins(ctx, agent.ID, since)
	read("logins", err)
	failures, err := e.facts.Failures(ctx, agent.ID, e.pass.WindowStart)
	read("failures", err)
	lockouts, err := e.facts.Lockouts(ctx, agent.ID, e.pass.WindowStart)
	read("failures", err)

	judge := func(id string, needs []string, j func() evaluator.Result) {
		for _, n := range needs {
			if failed[n] {
				return
			}
		}
		results[id] = j()
	}

	authLog := ProbeResult(e.probes[agent.ID], e.seen[agent.ID], e.pass.Now)
	configRun := runOf(settings.Snapshot)

	// EV-01: logging of accesses.
	judge("EV-01", []string{"config"}, func() evaluator.Result {
		in := EV01Input{Settings: settings, Log: authLog}
		in.Sources, in.SourcesProblem = listParam(policy, agent.ID, "P-03")
		return evaluator.Result{Judgement: JudgeEV01(in), RunID: configRun}
	})

	// EV-03: attempt limit.
	judge("EV-03", []string{"config", "pam"}, func() evaluator.Result {
		in := EV03Input{Settings: settings, PAM: pam}
		in.MaxAttempts, in.MaxAttemptsProblem = intParam(policy, agent.ID, "P-05")
		return evaluator.Result{Judgement: JudgeEV03(in), RunID: configRun}
	})

	// EV-04: failed attempts without lockout, in the window.
	judge("EV-04", []string{"failures"}, func() evaluator.Result {
		in := EV04Input{Failures: failures, Lockouts: lockouts, Log: authLog}
		in.MaxAttempts, in.MaxAttemptsProblem = intParam(policy, agent.ID, "P-05")
		return evaluator.Result{Judgement: JudgeEV04(in)}
	})

	// EV-05: credential age.
	judge("EV-05", []string{"identity", "config"}, func() evaluator.Result {
		in := EV05Input{Accounts: accounts, Settings: settings, Today: today}
		in.MaxAge, in.MaxAgeProblem = intParam(policy, agent.ID, "P-04")
		return evaluator.Result{Judgement: JudgeEV05(in), RunID: identityRun(accounts)}
	})

	// EV-07: remote channels used, in the window.
	judge("EV-07", []string{"logins"}, func() evaluator.Result {
		in := EV07Input{Log: authLog}
		for _, l := range logins {
			if !l.Time.Before(e.pass.WindowStart) {
				in.Logins = append(in.Logins, l)
			}
		}
		in.Channels, in.ChannelsProblem = columnParam(policy, agent.ID, "P-07", 0)
		return evaluator.Result{Judgement: JudgeEV07(in)}
	})

	// EV-09: re-authentication.
	judge("EV-09", []string{"sudoers", "pam"}, func() evaluator.Result {
		in := EV09Input{Sudoers: sudoers, PAM: pam}
		in.Points, in.PointsProblem = listParam(policy, agent.ID, "P-08")
		return evaluator.Result{Judgement: JudgeEV09(in), RunID: runOfSudoers(sudoers.Snapshot)}
	})

	// EV-10: accounts without use.
	judge("EV-10", []string{"identity", "logins"}, func() evaluator.Result {
		in := EV10Input{Accounts: accounts, Today: today, LastAlert: map[string]time.Time{}}
		for _, l := range logins {
			if l.Time.After(in.LastAlert[l.Account]) {
				in.LastAlert[l.Account] = l.Time
			}
		}
		in.MaxIdle, in.MaxIdleProblem = intParam(policy, agent.ID, "P-09")
		return evaluator.Result{Judgement: JudgeEV10(in), RunID: identityRun(accounts)}
	})

	// EV-11: password quality.
	judge("EV-11", []string{"pam", "config"}, func() evaluator.Result {
		in := EV11Input{PAM: pam, Settings: settings}
		in.Minimums, in.MinimumsProblem = minimumsParam(policy, agent.ID)
		return evaluator.Result{Judgement: JudgeEV11(in), RunID: runOfPAM(pam.Snapshot)}
	})

	// EV-12: what is shown before authenticating.
	judge("EV-12", []string{"config"}, func() evaluator.Result {
		in := EV12Input{Settings: settings}
		in.Allowed, in.AllowedProblem = listParam(policy, agent.ID, "P-11")
		return evaluator.Result{Judgement: JudgeEV12(in), RunID: configRun}
	})

	return results, errors.Join(errs...)
}

func (e *Evaluator) settings(ctx context.Context, agentID string, since time.Time) (Settings, error) {
	s, ok := e.configs[agentID]
	if !ok {
		return Settings{}, nil
	}
	files, err := e.facts.ConfigFiles(ctx, agentID, s.RunID, since)
	return Settings{Snapshot: &s, Files: files}, err
}

func (e *Evaluator) pam(ctx context.Context, agentID string, since time.Time) (PAM, error) {
	s, ok := e.pams[agentID]
	if !ok {
		return PAM{}, nil
	}
	rules, err := e.facts.PAMRules(ctx, agentID, s.RunID, since)
	return PAM{Snapshot: &s, Rules: rules}, err
}

func (e *Evaluator) accounts(ctx context.Context, agentID string, since time.Time) (Accounts, error) {
	list, ok := e.identities[agentID]
	if !ok || len(list) == 0 {
		return Accounts{}, nil
	}
	records, err := e.facts.IdentityRecords(ctx, agentID, list[0].RunID, since)
	return Accounts{Snapshot: &list[0], Records: records}, err
}

func (e *Evaluator) sudoersOf(ctx context.Context, agentID string, since time.Time) (Sudoers, error) {
	s, ok := e.sudoers[agentID]
	if !ok {
		return Sudoers{}, nil
	}
	grants, err := e.facts.SudoGrants(ctx, agentID, s.RunID, since)
	return Sudoers{Snapshot: &s, Grants: grants}, err
}

func runOf(s *fact.ConfigSnapshot) string {
	if s == nil {
		return ""
	}
	return s.RunID
}

func runOfPAM(s *fact.PAMSnapshot) string {
	if s == nil {
		return ""
	}
	return s.RunID
}

func runOfSudoers(s *fact.SudoersSnapshot) string {
	if s == nil {
		return ""
	}
	return s.RunID
}

func identityRun(a Accounts) string {
	if a.Snapshot == nil {
		return ""
	}
	return a.Snapshot.RunID
}

func listParam(policy params.Lister, agentID, id string) ([]string, string) {
	values, err := policy.List(agentID, control, id)
	if err != nil {
		return nil, err.Error()
	}
	return values, ""
}

func columnParam(policy params.Lister, agentID, id string, col int) ([]string, string) {
	values, err := policy.ListColumn(agentID, control, id, col)
	if err != nil {
		return nil, err.Error()
	}
	return values, ""
}

// intParam reads a whole, non-negative number (days, attempts).
func intParam(policy params.Lister, agentID, id string) (int, string) {

	n, err := policy.Number(agentID, control, id)
	if err != nil {
		return 0, err.Error()
	}

	if n < 0 || n != float64(int(n)) {
		return 0, fmt.Sprintf("%v is not a whole number of zero or more", n)
	}

	return int(n), ""
}

// minimumsParam reads P-10, "criterio | minimo" rows. An unknown criterion
// or a minimum that is not a number makes the whole table unusable.
func minimumsParam(policy params.Lister, agentID string) (map[string]int, string) {

	rows, err := policy.List(agentID, control, "P-10")
	if err != nil {
		return nil, err.Error()
	}

	known := map[string]bool{CriterionLength: true, CriterionClasses: true, CriterionHistory: true, CriterionBlocklist: true}
	minimums := map[string]int{}

	for _, row := range rows {

		criterion, value, _ := strings.Cut(row, "|")
		criterion, value = strings.TrimSpace(criterion), strings.TrimSpace(value)

		if !known[criterion] {
			return nil, fmt.Sprintf("unknown criterion %q", criterion)
		}

		n, err := strconv.Atoi(value)
		if err != nil || n < 0 {
			return nil, fmt.Sprintf("%s minimum %q is not a number", criterion, value)
		}

		minimums[criterion] = n
	}

	return minimums, ""
}

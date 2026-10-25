package opacc3

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

// Facts is what op.acc.3 reads (source.Source in production).
type Facts interface {
	AuditActions(ctx context.Context, since time.Time) ([]source.ActionCount, error)
	SudoActions(ctx context.Context, since time.Time) ([]source.ActionCount, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
}

const control = "op.acc.3"

// Evaluator judges op.acc.3. The actions of every machine are read once
// per pass, on the first agent: segregation is about people, who act on
// several machines.
type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	watches    map[string]fact.AuditWatchSnapshot
	configs    map[string]fact.WazuhAgentConfig
	identities map[string][]fact.IdentitySnapshot

	// The fleet of the pass, built on the first agent with its P-06.
	built   bool
	days    int
	actions []source.ActionCount
	readErr error
	nameErr error
	names   map[string]map[string]string
}

// NewEvaluator returns the op.acc.3 evaluator.
func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

// Control is the catalog id.
func (e *Evaluator) Control() string { return control }

// Begin reads the newest audit watch, Wazuh configuration and identity of
// every agent.
func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass, e.built, e.actions, e.readErr, e.nameErr = pass, false, nil, nil, nil
	e.names = map[string]map[string]string{}

	var err error
	if e.watches, err = e.facts.AuditWatchSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("audit watch snapshots: %w", err)
	}
	if e.configs, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("wazuh agent configs: %w", err)
	}
	if e.identities, err = e.facts.IdentitySnapshots(ctx, pass.WindowStart, 1); err != nil {
		return fmt.Errorf("identity snapshots: %w", err)
	}

	return nil
}

// Agent judges the seven evidences of op.acc.3 for one agent.
func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	in := Input{AgentID: agent.ID}
	var problems []string

	pairs, err := policy.List(agent.ID, control, "P-02")
	if err != nil {
		problems = append(problems, "P-02: "+err.Error())
	}
	in.Pairs = ParsePairs(pairs)

	functions, err := policy.List(agent.ID, control, "P-03")
	if err != nil {
		problems = append(problems, "P-03: "+err.Error())
	}
	in.Functions = ParseFunctions(functions)

	days, err := policy.Number(agent.ID, control, "P-06")
	if err != nil || days < 1 {
		problems = append(problems, fmt.Sprintf("P-06: %v", errOr(err, "must be at least one day")))
	}
	in.Problem = strings.Join(problems, "; ")

	if rows, err := policy.List(agent.ID, control, "P-04"); err != nil {
		in.TaskProblems = []string{err.Error()}
	} else {
		in.Tasks, in.TaskProblems = ParseTasks(rows)
	}

	if rows, err := policy.List(agent.ID, control, "P-05"); err == nil {
		for _, r := range rows {
			if c := cells(r); len(c) > 0 {
				in.Auditors = append(in.Auditors, c[0])
			}
		}
	}

	// The actions of the whole fleet, once per pass.
	if in.Problem == "" {
		if err := e.build(ctx, int(days)); err != nil {
			return nil, err
		}
		in.Fleet = BuildFleet(e.actions, in.Functions, in.Tasks, e.name)
	}

	var watches *fact.AuditWatchSnapshot
	if w, ok := e.watches[agent.ID]; ok {
		watches = &w
	}
	var config *fact.WazuhAgentConfig
	if c, ok := e.configs[agent.ID]; ok {
		config = &c
	}
	in.Chain = Chain(watches, config, in.Functions)

	results := map[string]evaluator.Result{
		"EV-01": {Judgement: JudgePair("EV-01", in)},
		"EV-02": {Judgement: JudgePair("EV-02", in)},
		"EV-03": {Judgement: JudgeTasks(in)},
		"EV-04": {Judgement: JudgePair("EV-04", in)},
		"EV-05": {Judgement: JudgeAuditors(in)},
		"EV-06": {Judgement: JudgeInventory(in)},
		"EV-07": {Judgement: JudgeSecurity(in)},
	}

	// An agent whose accounts could not be read leaves its uids unnamed:
	// EV-06 says so; the error is reported once per agent.
	return results, e.nameErr
}

// build reads the audited and sudo actions of every agent in the last P-06
// days, once per pass.
func (e *Evaluator) build(ctx context.Context, days int) error {

	if e.built && e.days == days {
		return e.readErr
	}
	e.built, e.days = true, days

	since := e.pass.Now.Add(-time.Duration(days) * 24 * time.Hour)

	audited, err := e.facts.AuditActions(ctx, since)
	if err != nil {
		e.readErr = fmt.Errorf("audit actions: %w", err)
		return e.readErr
	}
	sudo, err := e.facts.SudoActions(ctx, since)
	if err != nil {
		e.readErr = fmt.Errorf("sudo actions: %w", err)
		return e.readErr
	}

	e.actions = append(audited, sudo...)

	// The uids of each agent, for the audit records. One agent whose
	// accounts cannot be read does not stop the others.
	var errs []error
	for agentID, list := range e.identities {
		if len(list) == 0 {
			continue
		}
		records, err := e.facts.IdentityRecords(ctx, agentID, list[0].RunID, e.pass.LookbackStart)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		byUID := map[string]string{}
		for _, r := range records {
			uid := strconv.Itoa(r.UID)
			if _, seen := byUID[uid]; !seen {
				byUID[uid] = r.AccountName
			}
		}
		e.names[agentID] = byUID
	}

	e.nameErr = errors.Join(errs...)
	return nil
}

func (e *Evaluator) name(agentID, uid string) (string, bool) {
	name, ok := e.names[agentID][uid]
	return name, ok
}

func errOr(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}

package opacc3

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	AuditActions(ctx context.Context, since time.Time) ([]source.ActionCount, error)
	SudoActions(ctx context.Context, since time.Time) ([]source.ActionCount, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
}

const control = "op.acc.3"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	watches    map[string]fact.AuditWatchSnapshot
	configs    map[string]fact.WazuhAgentConfig
	identities map[string][]fact.IdentitySnapshot

	built   bool
	days    int
	actions []source.ActionCount
	readErr error
	nameErr error
	names   map[string]map[string]string
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

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

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	in := Input{AgentID: agent.ID}
	var problems []catalog.Message

	pairs, err := policy.List(agent.ID, control, "P-02")
	if err != nil {
		problems = append(problems, passes.Param("P-02", err))
	}
	in.Pairs = ParsePairs(pairs)

	functions, err := policy.List(agent.ID, control, "P-03")
	if err != nil {
		problems = append(problems, passes.Param("P-03", err))
	}
	in.Functions = ParseFunctions(functions)

	days, err := policy.Number(agent.ID, control, "P-06")
	switch {
	case err != nil:
		problems = append(problems, passes.Param("P-06", err))
	case days < 1:
		problems = append(problems, catalog.Says("opacc3.p06_one_day"))
	}
	in.Problem = passes.Problems(problems)

	if rows, err := policy.List(agent.ID, control, "P-04"); err != nil {
		in.TaskProblems = []catalog.Message{passes.Param("P-04", err)}
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

	if in.Problem.IsZero() {
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

	return results, e.nameErr
}

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

	var errs []error
	for agentID, list := range e.identities {
		if len(list) == 0 {
			continue
		}
		records, err := e.facts.IdentityRecords(ctx, agentID, list[0].RecordsRun(), e.pass.LookbackStart)
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

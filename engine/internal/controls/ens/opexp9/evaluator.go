package opexp9

import (
	"context"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	ActiveResponseTimes(ctx context.Context, since time.Time) (map[string][]time.Time, error)
	AlertsBetween(ctx context.Context, agentID string, from, to time.Time) (int, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
	TransactionSnapshots(ctx context.Context, since time.Time) (map[string]fact.TransactionSnapshot, error)
	PackageTransactions(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PackageTransaction, error)
}

const control = "op.exp.9"

type Evaluator struct {
	facts Facts

	pass         evaluator.Pass
	wazuh        map[string]fact.WazuhAgentConfig
	responses    map[string][]time.Time
	transactions map[string]fact.TransactionSnapshot
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	var err error
	if e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("wazuh config: %w", err)
	}
	if e.responses, err = e.facts.ActiveResponseTimes(ctx, pass.Now.Add(-opexp7.Horizon)); err != nil {
		return fmt.Errorf("active responses: %w", err)
	}
	if e.transactions, err = e.facts.TransactionSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("transactions: %w", err)
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	rows, err := policy.List(agent.ID, opexp7.Control, opexp7.RegisterParam)
	if err != nil {
		gap := passes.Gap(verdict.CauseConfiguration, passes.Param("op.exp.7 P-13", err))
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-07", "EV-08", "EV-09"} {
			put(id, gap)
		}
		return results, nil
	}
	incidents := opexp7.Of(opexp7.ParseRegister(rows), agent.Name, now)
	count := func(from, to time.Time) (int, error) { return e.facts.AlertsBetween(ctx, agent.ID, from, to) }

	put("EV-01", JudgeEV01(incidents, count))

	phases, err := policy.List(agent.ID, control, "P-02")
	put("EV-02", JudgeEV02(incidents, Due(phases), passes.ParamProblem("P-02", err)))

	put("EV-03", opexp7.JudgeEV06(incidents, e.responses[agent.ID], now))

	put("EV-04", func() verdict.Judgement {
		if len(incidents) == 0 {
			return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.changes_recorded", "count", 0))
		}
		since := now.Add(-opexp7.Horizon)
		fim, err := e.facts.FIMChanges(ctx, agent.ID, since)
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		var records []fact.PackageTransaction
		if s, ok := e.transactions[agent.ID]; ok {
			if records, err = e.facts.PackageTransactions(ctx, agent.ID, s.RecordsRun(), e.pass.LookbackStart); err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
			}
		}
		requests, err := policy.List(agent.ID, opexp5.Control, opexp5.RegisterParam)
		return JudgeEV04(incidents, opexp5.Changes(fim, records, since), opexp5.ParseRegister(requests), agent.Name, passes.ParamProblem("op.exp.5 P-10", err), now)
	}())

	var manager *fact.WazuhAgentConfig
	if m, ok := e.wazuh[source.ManagerID]; ok {
		manager = &m
	}
	put("EV-05", JudgeEV05(incidents, manager, now))
	put("EV-07", JudgeEV07(incidents, count, now))

	review, err := policy.List(agent.ID, control, "P-07")
	put("EV-08", JudgeEV08(incidents, review, passes.ParamProblem("P-07", err), now))
	put("EV-09", JudgeEV09(incidents))

	return results, nil
}

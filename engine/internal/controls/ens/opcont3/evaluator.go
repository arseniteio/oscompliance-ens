package opcont3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	MonitoringHistory(ctx context.Context, agentID string, since time.Time) ([]source.MonitoringRecord, error)
}

const control = "op.cont.3"

type Evaluator struct {
	facts Facts
	pass  evaluator.Pass
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	all := func(j verdict.Judgement) {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05"} {
			put(id, j)
		}
	}
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	months, problem := passes.Whole(policy, agent.ID, control, "P-01", "param.not_months")
	if !problem.IsZero() {
		all(passes.Gap(verdict.CauseConfiguration, problem))
		return results, nil
	}
	register, problem := list("P-04", false)
	if !problem.IsZero() {
		all(passes.Gap(verdict.CauseConfiguration, problem))
		return results, nil
	}
	tests := ParseTests(register)
	period := Since(tests, now.AddDate(0, -months, 0))

	kinds, kindsProblem := list("P-02", false)
	scenarios, scenariosProblem := list("P-03", true)

	put("EV-01", func() verdict.Judgement {
		if !kindsProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, kindsProblem)
		}
		return JudgeEV01(period, kinds)
	}())

	put("EV-02", func() verdict.Judgement {
		for _, p := range []catalog.Message{kindsProblem, scenariosProblem} {
			if !p.IsZero() {
				return passes.Gap(verdict.CauseConfiguration, p)
			}
		}
		return JudgeEV02(tests, kinds, scenarios, months, now)
	}())

	var measured []Measured
	for _, t := range period {
		if !t.Exercised() || !t.Involves(agent.Name) {
			continue
		}
		records, err := e.facts.MonitoringHistory(ctx, agent.ID, t.Start)
		if err != nil {
			return nil, fmt.Errorf("monitoring of %s: %w", agent.ID, err)
		}
		down, restored, seen := Downtime(records, t.Start, t.End.Add(followUp))
		measured = append(measured, Measured{Test: t, Down: down, Restored: restored, Seen: seen})
	}
	put("EV-03", JudgeEV03(measured))

	put("EV-04", func() verdict.Judgement {
		rto, problem := list("P-07", len(measured) == 0)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV04(measured, rto, agent.Name)
	}())

	put("EV-05", func() verdict.Judgement {
		rows, problem := list("P-05", true)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV05(tests, rows, now)
	}())

	return results, nil
}

package opcont2

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
}

const control = "op.cont.2"

type Evaluator struct {
	facts Facts

	pass  evaluator.Pass
	wazuh map[string]fact.WazuhAgentConfig
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
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	list := func(id string) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	put("EV-01", func() verdict.Judgement {
		plans, problem := list("P-01")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		months, problem := passes.Whole(policy, agent.ID, control, "P-08", "param.not_months")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV01(plans, months, now)
	}())

	put("EV-04", func() verdict.Judgement {
		rows, problem := list("P-04")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV04(rows, now)
	}())

	put("EV-06", func() verdict.Judgement {
		functions, problem := list("P-03")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		training, problem := list("P-05")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV06(functions, training, now)
	}())

	put("EV-03", func() verdict.Judgement {
		rows, problem := list("P-07")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		var paths []string
		for _, r := range rows {
			if p := Cells(r, 1)[0]; filepath.IsAbs(p) {
				paths = append(paths, filepath.Clean(p))
			}
		}
		var config *fact.WazuhAgentConfig
		if c, ok := e.wazuh[agent.ID]; ok {
			config = &c
		}
		return JudgeEV03(config, paths)
	}())

	return results, nil
}

package opmon1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	Detections(ctx context.Context, since time.Time) (map[string]source.Detection, error)
	GroupDetections(ctx context.Context, groups []string, since time.Time) (source.Detection, error)
	ActiveResponseTimes(ctx context.Context, since time.Time) (map[string][]time.Time, error)
}

const Control = "op.mon.1"

const Horizon = 90 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	reporting  map[string]source.Reporting
	wazuh      map[string]fact.WazuhAgentConfig
	detections map[string]source.Detection
	network    source.Detection
	responses  map[string][]time.Time
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return Control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.manager, e.managerErr = e.facts.Manager(ctx)

	var err error
	if e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	if e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("wazuh config: %w", err)
	}
	since := pass.Now.Add(-Horizon)
	if e.detections, err = e.facts.Detections(ctx, since); err != nil {
		return fmt.Errorf("detections: %w", err)
	}
	if e.network, err = e.facts.GroupDetections(ctx, NetworkGroups, since); err != nil {
		return fmt.Errorf("network detections: %w", err)
	}
	if e.responses, err = e.facts.ActiveResponseTimes(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("active responses: %w", err)
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	fromManager := func(judge func(m *source.Manager) verdict.Judgement) verdict.Judgement {
		if e.managerErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error()))
		}
		return judge(e.manager)
	}

	put("EV-01", fromManager(func(m *source.Manager) verdict.Judgement {
		sets, err := policy.List(agent.ID, Control, "P-02")
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-02", err))
		}
		return JudgeEV01(m, sets)
	}))

	put("EV-02", func() verdict.Judgement {
		hours, problem := passes.Whole(policy, agent.ID, Control, "P-09", "param.not_hours")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		r := ReportingOf(agent.ID, e.reporting, e.manager, now)
		var c *fact.WazuhAgentConfig
		if v, ok := e.wazuh[agent.ID]; ok {
			c = &v
		}
		return JudgeEV02(r, c, hours, now)
	}())

	days, daysProblem := passes.Whole(policy, agent.ID, Control, "P-08", "param.not_days")

	put("EV-03", func() verdict.Judgement {
		if !daysProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, daysProblem)
		}
		return JudgeEV03(e.detections[agent.ID], days, now)
	}())

	put("EV-04", fromManager(func(m *source.Manager) verdict.Judgement {
		rows, err := policy.List(agent.ID, Control, "P-03")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-03", err))
		}
		return JudgeEV04(m, rows)
	}))

	put("EV-05", func() verdict.Judgement {
		rows, err := policy.List(agent.ID, Control, "P-01")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-01", err))
		}
		if !daysProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, daysProblem)
		}
		return JudgeEV05(rows[0], e.network, days, now)
	}())

	put("EV-07", fromManager(func(m *source.Manager) verdict.Judgement {
		rows, err := policy.List(agent.ID, Control, "P-06")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-06", err))
		}
		return JudgeEV07(m, rows, len(e.responses[agent.ID]))
	}))

	put("EV-08", fromManager(func(m *source.Manager) verdict.Judgement {
		maxDays, problem := passes.Whole(policy, agent.ID, Control, "P-07", "param.not_days")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		approved, err := policy.List(agent.ID, Control, "P-05")
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-05", err))
		}
		return JudgeEV08(m, approved, maxDays, now)
	}))

	return results, nil
}

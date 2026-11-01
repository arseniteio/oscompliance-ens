package mps3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mps1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	DeviceSecurities(ctx context.Context, since time.Time) (map[string]fact.DeviceSecurity, error)
	MalwareProtections(ctx context.Context, since time.Time) (map[string]fact.MalwareProtection, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	Retention(ctx context.Context) (days int, found bool, err error)
}

const control = "mp.s.3"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	devices    map[string]fact.DeviceSecurity
	protection map[string]fact.MalwareProtection
	retention  int
	retained   bool
	hours      map[string][]time.Time
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours = map[string][]time.Time{}
	e.manager, e.managerErr = e.facts.Manager(ctx)
	var err error
	if e.devices, err = e.facts.DeviceSecurities(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if e.protection, err = e.facts.MalwareProtections(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("malware protection: %w", err)
	}
	if e.retention, e.retained, err = e.facts.Retention(ctx); err != nil {
		return fmt.Errorf("retention: %w", err)
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	gap := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }
	list := func(controlID, id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, controlID, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	put("EV-01", func() verdict.Judgement {
		rows, problem := list(control, "P-02", false)
		hours, hoursProblem := opmon1.Whole(policy, agent.ID, control, "P-12", "param.not_hours")
		for _, p := range []catalog.Message{problem, hoursProblem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		platform := mps1.ParsePlatform(rows)
		if len(platform.Sources) == 0 {
			return gap(catalog.Says("mps3.no_filter"))
		}
		elements, err := mps1.Activity(ctx, e.facts.SourceActivity, e.hours, platform.Sources, now.Add(-7*24*time.Hour))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return mpcom1.JudgeEV01(elements, hours, now)
	}())

	indicators, indicatorsProblem := list(control, "P-03", false)
	for _, f := range Filters {
		switch {
		case e.managerErr != nil:
			put(f.Evidence, passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error())))
		case !indicatorsProblem.IsZero():
			put(f.Evidence, gap(indicatorsProblem))
		default:
			put(f.Evidence, mpcom3.JudgeAttack(e.manager, indicators, f.Name))
		}
	}

	var device *fact.DeviceSecurity
	if d, ok := e.devices[agent.ID]; ok {
		device = &d
	}
	put("EV-05", func() verdict.Judgement {
		resolvers, problem := list(control, "P-04", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV05(device, resolvers)
	}())

	put("EV-06", func() verdict.Judgement {
		var p *fact.MalwareProtection
		if v, ok := e.protection[agent.ID]; ok {
			p = &v
		}
		expected, problem := list("op.exp.6", "P-02", true)
		return opexp6.JudgeEV01(p, expected, problem)
	}())

	put("EV-08", func() verdict.Judgement {
		days, problem := opmon1.Whole(policy, agent.ID, control, "P-08", "param.not_days")
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV08(e.retention, e.retained, days)
	}())

	review := func(register, period string) verdict.Judgement {
		rows, problem := list(control, register, false)
		days, daysProblem := opmon1.Whole(policy, agent.ID, control, period, "param.not_days")
		j, _ := passes.Review(rows, problem, register, days, daysProblem, period, now)
		return j
	}
	put("EV-12", review("P-06", "P-09"))
	put("EV-13", review("P-07", "P-10"))

	return results, nil
}

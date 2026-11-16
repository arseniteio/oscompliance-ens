package mpeq3

import (
	"context"
	"errors"
	"fmt"
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
	DeviceSecurities(ctx context.Context, since time.Time) (map[string]fact.DeviceSecurity, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	KeySnapshots(ctx context.Context, since time.Time) (map[string]fact.KeySnapshot, error)
	KeyRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.KeyRecord, error)
}

const control = "mp.eq.3"

type Evaluator struct {
	facts Facts

	pass      evaluator.Pass
	devices   map[string]fact.DeviceSecurity
	reporting map[string]source.Reporting
	keys      map[string]fact.KeySnapshot
	decisions map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}
	var err error
	if e.devices, err = e.facts.DeviceSecurities(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	if e.keys, err = e.facts.KeySnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	return nil
}

func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	gap := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	var device *fact.DeviceSecurity
	if d, ok := e.devices[agent.ID]; ok {
		device = &d
	}
	inventory, inventoryProblem := list("P-01", true)
	entry, inventoried := Entry(inventory, agent.Name)

	if !inventoried && (device == nil || !device.Portable) {
		out := verdict.Explain(verdict.NotApplicable, "", catalog.Says("mpeq3.not_portable"))
		e.decisions[agent.ID] = map[string]verdict.Judgement{}
		if c, ok := catalog.LookupControl(control); ok {
			for _, ev := range c.Evidences {
				put(ev.ID, out)
			}
			for _, r := range c.Requirements {
				e.decisions[agent.ID][r.ID] = out
			}
		}
		return results, nil
	}

	put("EV-01", func() verdict.Judgement {
		if !inventoryProblem.IsZero() {
			return gap(inventoryProblem)
		}
		return JudgeEV01(entry, inventoried)
	}())

	put("EV-02", func() verdict.Judgement {
		days, problem := passes.Whole(policy, agent.ID, control, "P-02", "param.not_days")
		if !problem.IsZero() {
			return gap(problem)
		}
		checks, problem := list("P-09", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		var r *source.Reporting
		if v, ok := e.reporting[agent.ID]; ok {
			r = &v
		}
		return JudgeEV02(r, checks, agent.Name, days, now)
	}())

	put("EV-03", func() verdict.Judgement {
		allowed, problem := list("P-05", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		s, ok := e.keys[agent.ID]
		if !ok {
			return JudgeEV03(nil, nil, allowed)
		}
		keys, err := e.facts.KeyRecords(ctx, agent.ID, s.RecordsRun(), e.pass.LookbackStart)
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return JudgeEV03(&s, keys, allowed)
	}())

	put("EV-04", func() verdict.Judgement {
		if !inventoried {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.not_inventoried"))
		}
		return JudgeEV04(device, entry[3])
	}())

	put("EV-06", func() verdict.Judgement {
		hours, problem := passes.Whole(policy, agent.ID, control, "P-08", "param.not_hours")
		if !problem.IsZero() {
			return gap(problem)
		}
		losses, problem := list("P-10", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV06(losses, agent.Name, hours)
	}())

	return results, nil
}

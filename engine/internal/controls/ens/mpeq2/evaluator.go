package mpeq2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	DeviceSecurities(ctx context.Context, since time.Time) (map[string]fact.DeviceSecurity, error)
	Processes(ctx context.Context, names []string) (map[string][]string, error)
}

const control = "mp.eq.2"

type Evaluator struct {
	facts Facts

	pass      evaluator.Pass
	devices   map[string]fact.DeviceSecurity
	processes map[string][]string
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
	e.processes = nil
	return nil
}

func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

func (e *Evaluator) leaveOut(agentID string, why catalog.Message) map[string]evaluator.Result {
	out := verdict.Explain(verdict.NotApplicable, "", why)
	results := map[string]evaluator.Result{}
	e.decisions[agentID] = map[string]verdict.Judgement{}
	if c, ok := catalog.LookupControl(control); ok {
		for _, ev := range c.Evidences {
			results[ev.ID] = evaluator.Result{Judgement: out}
		}
		for _, r := range c.Requirements {
			e.decisions[agentID][r.ID] = out
		}
	}
	return results
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	var device *fact.DeviceSecurity
	if d, ok := e.devices[agent.ID]; ok {
		device = &d
	}

	workstation, err := policy.Bool(agent.ID, control, "P-03")
	switch {
	case errors.Is(err, params.ErrNotSet):
		workstation = device != nil && device.Graphical
	case err != nil:
		workstation = true
	}
	if !workstation {
		return e.leaveOut(agent.ID, catalog.Says("mpeq2.not_workstation")), nil
	}
	exceptions, _ := policy.List(agent.ID, control, "P-04")
	if slices.ContainsFunc(exceptions, func(r string) bool { return strings.EqualFold(opcont2.Cells(r, 1)[0], agent.Name) }) {
		return e.leaveOut(agent.ID, catalog.Says("mpeq2.exception")), nil
	}

	lock, lockProblem := passes.Whole(policy, agent.ID, control, "P-01", "param.not_minutes")
	put("EV-01", func() verdict.Judgement {
		if !lockProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, lockProblem)
		}
		return JudgeEV01(device, lock)
	}())

	put("EV-02", func() verdict.Judgement {
		cancel, problem := passes.Whole(policy, agent.ID, control, "P-02", "param.not_minutes")
		for _, p := range []catalog.Message{lockProblem, problem} {
			if !p.IsZero() {
				return passes.Gap(verdict.CauseConfiguration, p)
			}
		}
		return JudgeEV02(device, lock, cancel)
	}())

	put("EV-05", func() verdict.Judgement {
		inhibitors, err := policy.List(agent.ID, control, "P-05")
		if errors.Is(err, params.ErrNotSet) {
			inhibitors, err = Inhibitors, nil
		}
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-05", err))
		}
		running, err := e.running(ctx, inhibitors)
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return JudgeEV05(running[agent.ID], inhibitors)
	}())

	return results, nil
}

func (e *Evaluator) running(ctx context.Context, names []string) (map[string][]string, error) {
	if e.processes == nil {
		p, err := e.facts.Processes(ctx, names)
		if err != nil {
			return nil, err
		}
		e.processes = p
	}
	return e.processes, nil
}

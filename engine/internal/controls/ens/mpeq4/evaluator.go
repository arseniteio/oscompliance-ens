package mpeq4

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	NeighbourSnapshots(ctx context.Context, since time.Time) (map[string]fact.NeighbourSnapshot, error)
	Networks(ctx context.Context, tools []string) (map[string]*source.Network, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	AcceptedFlows(ctx context.Context, names []string, since time.Time) ([]source.Flow, error)
}

const control = "mp.eq.4"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	neighbours map[string]fact.NeighbourSnapshot
	fleet      map[string]bool
	hours      map[string][]time.Time
	flows      map[string][]source.Flow
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours, e.flows, e.fleet = map[string][]time.Time{}, map[string][]source.Flow{}, map[string]bool{}
	var err error
	if e.neighbours, err = e.facts.NeighbourSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("neighbours: %w", err)
	}
	networks, err := e.facts.Networks(ctx, mpcom1.TunnelTools)
	if err != nil {
		return fmt.Errorf("networks: %w", err)
	}
	for _, n := range networks {
		for _, a := range n.Addresses {
			e.fleet[a] = true
		}
	}
	return nil
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

	var neighbours *fact.NeighbourSnapshot
	if n, ok := e.neighbours[agent.ID]; ok {
		neighbours = &n
	}
	inventory, inventoryProblem := list("P-01", false)
	devices := ParseDevices(inventory)

	put("EV-01", JudgeEV01(neighbours))

	put("EV-02", func() verdict.Judgement {
		if !inventoryProblem.IsZero() {
			return gap(inventoryProblem)
		}
		return JudgeEV02(neighbours, devices, e.fleet)
	}())

	logging, loggingProblem := list("P-04", true)
	var elements []mpcom1.Element
	for _, r := range logging {
		if c := cells(r, 3); c[2] != "" {
			elements = append(elements, mpcom1.Element{Name: c[0], Source: c[2]})
		}
	}
	sources, sourcesProblem := list("P-03", true)
	var flowSources []string
	for _, r := range sources {
		if c := cells(r, 3); c[2] != "" {
			flowSources = append(flowSources, c[2])
		}
	}
	elements, flows, err := e.activity(ctx, elements, flowSources)
	if err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}

	put("EV-03", func() verdict.Judgement {
		rules, problem := list("P-02", false)
		for _, p := range []catalog.Message{inventoryProblem, sourcesProblem, problem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		if len(flowSources) == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("mpeq4.no_flow_sources"))
		}
		return JudgeEV03(flows, devices, rules)
	}())

	put("EV-04", func() verdict.Judgement {
		hours, problem := opmon1.Whole(policy, agent.ID, control, "P-06", "param.not_hours")
		for _, p := range []catalog.Message{loggingProblem, problem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		if len(elements) == 0 {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq4.no_device_logs"))
		}
		return mpcom1.JudgeEV01(elements, hours, now)
	}())

	put("EV-08", func() verdict.Judgement {
		wipes, problem := list("P-05", true)
		for _, p := range []catalog.Message{inventoryProblem, problem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		return JudgeEV08(devices, wipes)
	}())

	return results, nil
}

// activity reads the devices' logs and flows once a pass: they are the organisation's, not the machine's.
func (e *Evaluator) activity(ctx context.Context, elements []mpcom1.Element, flowSources []string) ([]mpcom1.Element, []source.Flow, error) {
	for i, el := range elements {
		h, ok := e.hours[el.Source]
		if !ok {
			var err error
			if h, err = e.facts.SourceActivity(ctx, el.Source, e.pass.Now.Add(-7*24*time.Hour)); err != nil {
				return nil, nil, err
			}
			e.hours[el.Source] = h
		}
		elements[i].Hours = h
	}
	key := fmt.Sprint(flowSources)
	flows, ok := e.flows[key]
	if !ok {
		var err error
		if flows, err = e.facts.AcceptedFlows(ctx, flowSources, e.pass.WindowStart); err != nil {
			return nil, nil, err
		}
		e.flows[key] = flows
	}
	return elements, flows, nil
}

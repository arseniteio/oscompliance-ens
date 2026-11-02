package mpcom1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Networks(ctx context.Context, tools []string) (map[string]*source.Network, error)
	RemoteLogins(ctx context.Context, since time.Time) (map[string][]source.RemoteLogin, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	AcceptedFlows(ctx context.Context, names []string, since time.Time) ([]source.Flow, error)
}

const control = "mp.com.1"

const continuity = 7 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass     evaluator.Pass
	networks map[string]*source.Network
	logins   map[string][]source.RemoteLogin
	hours    map[string][]time.Time
	flows    map[string][]source.Flow
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours = map[string][]time.Time{}
	e.flows = map[string][]source.Flow{}
	var err error
	if e.networks, err = e.facts.Networks(ctx, TunnelTools); err != nil {
		return fmt.Errorf("networks: %w", err)
	}
	if e.logins, err = e.facts.RemoteLogins(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("remote logins: %w", err)
	}
	return nil
}

func (e *Evaluator) activity(ctx context.Context, elements []Element) ([]Element, []source.Flow, error) {

	var names []string
	for i, el := range elements {
		h, ok := e.hours[el.Source]
		if !ok {
			var err error
			if h, err = e.facts.SourceActivity(ctx, el.Source, e.pass.Now.Add(-continuity)); err != nil {
				return nil, nil, err
			}
			e.hours[el.Source] = h
		}
		elements[i].Hours = h
		names = append(names, el.Source)
	}

	key := fmt.Sprint(names)
	flows, ok := e.flows[key]
	if !ok {
		var err error
		if flows, err = e.facts.AcceptedFlows(ctx, names, e.pass.WindowStart); err != nil {
			return nil, nil, err
		}
		e.flows[key] = flows
	}
	return elements, flows, nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}
	gap := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }

	rows, elementsProblem := list("P-01", false)
	hours, hoursProblem := passes.Whole(policy, agent.ID, control, "P-10", "param.not_hours")
	authorised, flowsProblem := list("P-02", false)

	elements, flows, err := e.activity(ctx, Sources(rows))
	if err != nil {
		return nil, fmt.Errorf("perimeter: %w", err)
	}

	switch {
	case !elementsProblem.IsZero():
		put("EV-01", gap(elementsProblem))
		put("EV-08", gap(elementsProblem))
	case !hoursProblem.IsZero():
		put("EV-01", gap(hoursProblem))
		put("EV-08", gap(hoursProblem))
	default:
		put("EV-01", JudgeEV01(elements, hours, now))
		put("EV-08", JudgeEV08(elements, hours, now.Add(-continuity), now))
	}

	put("EV-02", func() verdict.Judgement {
		for _, p := range []catalog.Message{elementsProblem, flowsProblem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		return JudgeEV02(flows, authorised)
	}())

	network := e.networks[agent.ID]

	put("EV-03", func() verdict.Judgement {
		patterns, problem := list("P-07", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV03(network, patterns)
	}())

	put("EV-04", func() verdict.Judgement {
		exits, problem := list("P-03", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV04(network, exits)
	}())

	put("EV-05", func() verdict.Judgement {
		allowed, problem := list("P-08", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV05(network, allowed)
	}())

	put("EV-06", func() verdict.Judgement {
		if !flowsProblem.IsZero() {
			return gap(flowsProblem)
		}
		reviews, reviewsProblem := list("P-11", false)
		days, daysProblem := passes.Whole(policy, agent.ID, control, "P-04", "param.not_days")
		return JudgeEV06(authorised, reviews, reviewsProblem, days, daysProblem, now)
	}())

	put("EV-07", func() verdict.Judgement {
		allowed, problem := list("P-09", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV07(e.logins[agent.ID], allowed)
	}())

	return results, nil
}

package opexp1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Inventories(ctx context.Context) (map[string]*source.Inventory, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error)
	NeighbourSnapshots(ctx context.Context, since time.Time) (map[string]fact.NeighbourSnapshot, error)
	PackageChanges(ctx context.Context, since time.Time) (map[string]map[time.Time]int, error)
}

const control = "op.exp.1"

// Package changes are counted back to the oldest review a register may reasonably hold.
const changesHorizon = 366 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass        evaluator.Pass
	inventories map[string]*source.Inventory
	reporting   map[string]source.Reporting
	wazuh       map[string]fact.WazuhAgentConfig
	neighbours  map[string]fact.NeighbourSnapshot
	changes     map[string]map[time.Time]int
	agentIPs    map[string]bool
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	w := pass.WindowStart
	var listening map[string]fact.ListeningSnapshot

	steps := []struct {
		name string
		do   func() error
	}{
		{"inventory", func() (err error) { e.inventories, err = e.facts.Inventories(ctx); return }},
		{"monitoring", func() (err error) { e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"listening", func() (err error) { listening, err = e.facts.ListeningSnapshots(ctx, w); return }},
		{"neighbours", func() (err error) { e.neighbours, err = e.facts.NeighbourSnapshots(ctx, w); return }},
		{"package changes", func() (err error) {
			e.changes, err = e.facts.PackageChanges(ctx, pass.Now.Add(-changesHorizon))
			return
		}},
	}

	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	// Every address of a machine with an agent, from any source that names it: Syscollector does not
	// index the manager, the oscompliance agent does report its addresses.
	e.agentIPs = map[string]bool{}
	for _, inv := range e.inventories {
		for _, ip := range inv.Addresses {
			e.agentIPs[ip] = true
		}
	}
	for _, r := range e.reporting {
		e.agentIPs[r.IP] = true
	}
	for _, l := range listening {
		for _, ip := range l.Addresses {
			e.agentIPs[ip] = true
		}
	}
	delete(e.agentIPs, "")
	delete(e.agentIPs, "any")

	return nil
}

func (e *Evaluator) Agent(_ context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	manager := agent.ID == source.ManagerID

	maxHours, hoursProblem := whole(policy, agent.ID, "P-08", "param.not_hours")

	var reporting *source.Reporting
	if r, ok := e.reporting[agent.ID]; ok {
		reporting = &r
	}
	f := Freshness{Reporting: reporting, Manager: manager, MaxHours: maxHours, HoursProblem: hoursProblem, Now: now}
	if c, ok := e.wazuh[agent.ID]; ok {
		f.Config = &c
	}
	inv := e.inventories[agent.ID]

	results := map[string]evaluator.Result{
		"EV-01": {Judgement: JudgeEV01(inv, f)},
		"EV-02": {Judgement: JudgeEV02(inv, f)},
		"EV-03": {Judgement: JudgeEV03(inv, f)},
		"EV-04": {Judgement: JudgeEV04(reporting, manager, maxHours, hoursProblem, now)},
	}

	var neighbours *fact.NeighbourSnapshot
	if n, ok := e.neighbours[agent.ID]; ok {
		neighbours = &n
	}
	declared, err := policy.ListColumn(agent.ID, control, "P-02", 2)
	results["EV-05"] = evaluator.Result{Judgement: JudgeEV05(neighbours, declared, problemOf("P-02", err), e.agentIPs)}

	reviews, err := policy.List(agent.ID, control, ReviewParam)
	days, daysProblem := whole(policy, agent.ID, "P-04", "param.not_days")
	results["EV-06"] = evaluator.Result{Judgement: JudgeEV06(reviews, problemOf(ReviewParam, err), days, daysProblem, e.changes[agent.ID], now)}

	assets, err := policy.List(agent.ID, control, "P-01")
	natures, naturesErr := policy.List(agent.ID, control, "P-03")
	naturesProblem := catalog.Message{}
	if naturesErr != nil && !errors.Is(naturesErr, params.ErrNotSet) {
		naturesProblem = passes.Param("P-03", naturesErr)
	}
	results["EV-07"] = evaluator.Result{Judgement: JudgeEV07(agent.Name, assets, problemOf("P-01", err), natures, naturesProblem)}

	return results, nil
}

// whole reads a parameter that must be a whole number of at least one.
func whole(policy params.Lister, agentID, id, notWhole string) (int, catalog.Message) {

	v, err := policy.Number(agentID, control, id)
	if err != nil {
		return 0, passes.Param(id, err)
	}
	if v < 1 || v != float64(int(v)) {
		return 0, catalog.Says(notWhole, "param", id, "value", v)
	}
	return int(v), catalog.Message{}
}

func problemOf(id string, err error) catalog.Message {
	if err != nil {
		return passes.Param(id, err)
	}
	return catalog.Message{}
}

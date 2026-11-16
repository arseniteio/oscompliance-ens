package mps4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mps1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/scope"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	DeviceSecurities(ctx context.Context, since time.Time) (map[string]fact.DeviceSecurity, error)
	FirewallSnapshots(ctx context.Context, since time.Time) (map[string]fact.FirewallSnapshot, error)
	ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error)
	ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
}

const control = "mp.s.4"

const dos = "denegacion_de_servicio"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	devices    map[string]fact.DeviceSecurity
	firewalls  map[string]fact.FirewallSnapshot
	listening  map[string]fact.ListeningSnapshot
	fleet      scope.Fleet
	decisions  map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}
	e.manager, e.managerErr = e.facts.Manager(ctx)
	var err error
	if e.devices, err = e.facts.DeviceSecurities(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	if e.firewalls, err = e.facts.FirewallSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("firewalls: %w", err)
	}
	if e.listening, err = e.facts.ListeningSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	reporting, err := e.facts.Reporting(ctx, pass.LookbackStart)
	if err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	e.fleet = scope.FleetOf(reporting)
	return nil
}

func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	gapOf := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}
	fromManager := func(judge func(m *source.Manager) verdict.Judgement) verdict.Judgement {
		if e.managerErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error()))
		}
		return judge(e.manager)
	}

	services, problem := list("P-01", false)
	if !problem.IsZero() {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-06", "EV-07", "EV-09", "EV-10"} {
			put(id, gapOf(problem))
		}
		return results, nil
	}
	exposed, reported := false, false
	for _, r := range services {
		machine := cells(r, 2)[1]
		exposed = exposed || strings.EqualFold(machine, agent.Name)
		reported = reported || e.fleet.Has(machine)
	}
	carrier := !exposed
	if carrier && (reported || !scope.Carrier(agent.ID)) {
		return mps1.OutOfScope(control, catalog.Says("mps4.not_exposed"), e.decisions, agent.ID), nil
	}
	onMachine := func(judge func() verdict.Judgement) verdict.Judgement {
		if carrier {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.no_service_machine"))
		}
		return judge()
	}

	var device *fact.DeviceSecurity
	if d, ok := e.devices[agent.ID]; ok {
		device = &d
	}

	put("EV-01", onMachine(func() verdict.Judgement {
		max, problem := passes.Whole(policy, agent.ID, control, "P-02", "param.not_percent")
		if !problem.IsZero() {
			return gapOf(problem)
		}
		return JudgeEV01(device, max)
	}))

	put("EV-02", onMachine(func() verdict.Judgement {
		var fw *fact.FirewallSnapshot
		if f, ok := e.firewalls[agent.ID]; ok {
			fw = &f
		}
		return JudgeEV02(device, fw)
	}))

	indicators, indicatorsProblem := list("P-03", false)
	put("EV-03", fromManager(func(m *source.Manager) verdict.Judgement {
		if !indicatorsProblem.IsZero() {
			return gapOf(indicatorsProblem)
		}
		return mpcom3.JudgeAttack(m, indicators, dos)
	}))
	put("EV-07", fromManager(func(m *source.Manager) verdict.Judgement {
		if !indicatorsProblem.IsZero() {
			return gapOf(indicatorsProblem)
		}
		return JudgeEV07(m, DoSRules(m, indicators))
	}))

	episodes, episodesProblem := list("P-07", true)
	put("EV-06", func() verdict.Judgement {
		if !episodesProblem.IsZero() {
			return gapOf(episodesProblem)
		}
		return JudgeEV06(episodes)
	}())
	put("EV-10", func() verdict.Judgement {
		if !episodesProblem.IsZero() {
			return gapOf(episodesProblem)
		}
		return JudgeEV10(episodes)
	}())

	put("EV-09", onMachine(func() verdict.Judgement {
		allowed, problem := list("P-08", true)
		if !problem.IsZero() {
			return gapOf(problem)
		}
		s, ok := e.listening[agent.ID]
		if !ok {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ListeningSnapshotFact))
		}
		sockets, err := e.facts.ListeningSockets(ctx, agent.ID, s.RecordsRun(), e.pass.LookbackStart)
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return JudgeEV09(sockets, allowed)
	}))

	return results, nil
}

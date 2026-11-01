package mps2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mps1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	Vulnerabilities(ctx context.Context) (map[string][]source.VulnerabilityDay, error)
}

const control = "mp.s.2"

// The requirements each modality of audit of P-07 answers.
var modalityRequirements = map[string][]string{
	BlackBox: {"mp.s.2.r1.1", "mp.s.2.r1.2"},
	WhiteBox: {"mp.s.2.r2.1", "mp.s.2.r2.2", "mp.s.2.r2.3"},
}

type Evaluator struct {
	facts Facts

	pass            evaluator.Pass
	manager         *source.Manager
	managerErr      error
	vulnerabilities map[string][]source.VulnerabilityDay
	hours           map[string][]time.Time
	decisions       map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours, e.decisions = map[string][]time.Time{}, map[string]map[string]verdict.Judgement{}
	e.manager, e.managerErr = e.facts.Manager(ctx)
	var err error
	if e.vulnerabilities, err = e.facts.Vulnerabilities(ctx); err != nil {
		return fmt.Errorf("vulnerabilities: %w", err)
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

	rows, problem := list("P-01", false)
	if !problem.IsZero() {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-06", "EV-07", "EV-08", "EV-10", "EV-11", "EV-12"} {
			put(id, gap(problem))
		}
		return results, nil
	}
	platform := mps1.ParsePlatform(rows)
	if !platform.Runs(agent.Name) {
		return mps1.OutOfScope(control, catalog.Says("mps2.not_web"), e.decisions, agent.ID), nil
	}
	var apps []string
	for _, r := range rows {
		if c := cells(r, 3); strings.EqualFold(c[1], agent.Name) {
			apps = append(apps, c[0])
		}
	}

	put("EV-01", func() verdict.Judgement {
		hours, problem := opmon1.Whole(policy, agent.ID, control, "P-11", "param.not_hours")
		if !problem.IsZero() {
			return gap(problem)
		}
		var mine []mpcom1.Element
		for _, r := range rows {
			if c := cells(r, 3); strings.EqualFold(c[1], agent.Name) && c[2] != "" {
				mine = append(mine, mpcom1.Element{Name: c[0], Source: c[2]})
			}
		}
		elements, err := mps1.Activity(ctx, e.facts.SourceActivity, e.hours, mine, now.Add(-7*24*time.Hour))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return mpcom1.JudgeEV01(elements, hours, now)
	}())

	indicators, indicatorsProblem := list("P-03", false)
	for _, a := range Attacks {
		switch {
		case e.managerErr != nil:
			put(a.Evidence, passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error())))
		case !indicatorsProblem.IsZero():
			put(a.Evidence, gap(indicatorsProblem))
		default:
			put(a.Evidence, mpcom3.JudgeAttack(e.manager, indicators, a.Name))
		}
	}

	put("EV-10", func() verdict.Judgement {
		days, problem := opmon1.Whole(policy, agent.ID, control, "P-09", "param.not_days")
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV10(e.vulnerabilities[agent.ID], days, now)
	}())

	modalityRows, modalityProblem := list("P-07", false)
	modality := ""
	if modalityProblem.IsZero() {
		modality = Modality(modalityRows[0])
		// Black box audits alone are no option at ALTO: the white box reinforcements stay to be met.
		if modality == BlackBox && policy.Level() == "ALTO" {
			modality = WhiteBox
		}
		e.decisions[agent.ID] = map[string]verdict.Judgement{}
		for m, reqs := range modalityRequirements {
			if m == modality {
				continue
			}
			for _, r := range reqs {
				e.decisions[agent.ID][r] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("mps2.modality", "modality", modalityRows[0]))
			}
		}
	}

	put("EV-11", func() verdict.Judgement {
		audits, problem := list("P-08", false)
		days, daysProblem := opmon1.Whole(policy, agent.ID, control, "P-10", "param.not_days")
		for _, p := range []catalog.Message{modalityProblem, problem, daysProblem} {
			if !p.IsZero() {
				return gap(p)
			}
		}
		return JudgeEV11(apps, audits, modality, days, now)
	}())

	put("EV-12", func() verdict.Judgement {
		findings, problem := list("P-12", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV12(apps, findings, now)
	}())

	return results, nil
}

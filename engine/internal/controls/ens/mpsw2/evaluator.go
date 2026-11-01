package mpsw2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mps1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	InstalledVersions(ctx context.Context, ids []string, since time.Time) (map[string]map[string]time.Time, error)
	SCARegressions(ctx context.Context, since time.Time) (map[string][]source.SCARegression, error)
	ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error)
	ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error)
	PackageVulnerabilities(ctx context.Context, packages []string) (map[string][]source.PackageVulnerability, error)
}

const control = "mp.sw.2"

// Deployments are judged this far back.
const Horizon = 90 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass            evaluator.Pass
	ids             map[string]string
	regressions     map[string][]source.SCARegression
	listening       map[string]fact.ListeningSnapshot
	vulnerabilities map[string][]source.PackageVulnerability
	decisions       map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.ids, e.decisions, e.vulnerabilities = map[string]string{}, map[string]map[string]verdict.Judgement{}, nil
	reporting, err := e.facts.Reporting(ctx, pass.LookbackStart)
	if err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	for id, r := range reporting {
		e.ids[strings.ToLower(r.Name)] = id
	}
	if e.regressions, err = e.facts.SCARegressions(ctx, pass.Now.Add(-Horizon)); err != nil {
		return fmt.Errorf("sca regressions: %w", err)
	}
	if e.listening, err = e.facts.ListeningSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("listening: %w", err)
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
	query := func(err error) verdict.Judgement {
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
	}

	rows, problem := list("P-01", false)
	if !problem.IsZero() {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-07"} {
			put(id, gap(problem))
		}
		return results, nil
	}
	apps := AppsOf(rows, agent.Name)
	if len(apps) == 0 {
		return mps1.OutOfScope(control, catalog.Says("mpsw2.no_apps"), e.decisions, agent.ID), nil
	}

	since := now.Add(-Horizon)
	installed, err := e.facts.InstalledVersions(ctx, []string{agent.ID}, since)
	if err != nil {
		return nil, fmt.Errorf("installed versions: %w", err)
	}
	deployments := Deployments(apps, installed[agent.ID])

	put("EV-01", JudgeEV01(apps, deployments))

	put("EV-02", func() verdict.Judgement {
		acceptances, problem := list("P-06", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV02(deployments, acceptances)
	}())

	put("EV-03", func() verdict.Judgement {
		days, problem := opmon1.Whole(policy, agent.ID, control, "P-04", "param.not_days")
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV03(deployments, e.regressions[agent.ID], days)
	}())

	put("EV-04", func() verdict.Judgement {
		declared, problem := list("P-05", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		s, ok := e.listening[agent.ID]
		if !ok {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ListeningSnapshotFact))
		}
		sockets, err := e.facts.ListeningSockets(ctx, agent.ID, s.RecordsRun(), e.pass.LookbackStart)
		if err != nil {
			return query(err)
		}
		return JudgeEV04(sockets, apps, declared)
	}())

	put("EV-05", func() verdict.Judgement {
		if e.vulnerabilities == nil {
			var packages []string
			for _, r := range rows {
				packages = append(packages, names(cells(r, 3)[2])...)
			}
			v, err := e.facts.PackageVulnerabilities(ctx, packages)
			if err != nil {
				return query(err)
			}
			e.vulnerabilities = v
		}
		return JudgeEV05(apps, e.vulnerabilities[agent.ID])
	}())

	put("EV-07", func() verdict.Judgement {
		pairs, problem := list("P-03", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		preproduction := ""
		for _, r := range pairs {
			if c := cells(r, 2); strings.EqualFold(c[0], agent.Name) {
				preproduction = c[1]
			}
		}
		var there map[string]time.Time
		if id, ok := e.ids[strings.ToLower(preproduction)]; ok {
			versions, err := e.facts.InstalledVersions(ctx, []string{id}, since)
			if err != nil {
				return query(err)
			}
			there = versions[id]
		}
		return JudgeEV07(deployments, preproduction, there)
	}())

	return results, nil
}

package mps1

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/scope"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
	TXT(ctx context.Context, name string) ([]string, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
}

const control = "mp.s.1"

// Filters of mp.s.1 as P-03 names them.
const (
	Antispam    = "antispam"
	Antimalware = "antimalware"
	MobileCode  = "codigo_movil"
)

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	configs    map[string]fact.ConfigSnapshot
	hours      map[string][]time.Time
	domains    map[string]Domain
	fleet      scope.Fleet
	decisions  map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours, e.domains, e.decisions = map[string][]time.Time{}, map[string]Domain{}, map[string]map[string]verdict.Judgement{}
	e.manager, e.managerErr = e.facts.Manager(ctx)
	var err error
	if e.configs, err = e.facts.ConfigSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("config: %w", err)
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

// OutOfScope makes a control NOT_APPLICABLE on a machine, evidences and requirements.
func OutOfScope(controlID string, why catalog.Message, decisions map[string]map[string]verdict.Judgement, agentID string) map[string]evaluator.Result {
	out := verdict.Explain(verdict.NotApplicable, "", why)
	results := map[string]evaluator.Result{}
	decisions[agentID] = map[string]verdict.Judgement{}
	if c, ok := catalog.LookupControl(controlID); ok {
		for _, ev := range c.Evidences {
			results[ev.ID] = evaluator.Result{Judgement: out}
		}
		for _, r := range c.Requirements {
			decisions[agentID][r.ID] = out
		}
	}
	return results
}

// Activity reads the hours with logs of each source once, into a cache kept for the pass.
func Activity(ctx context.Context, read func(ctx context.Context, name string, since time.Time) ([]time.Time, error), cache map[string][]time.Time, elements []mpcom1.Element, since time.Time) ([]mpcom1.Element, error) {
	for i, el := range elements {
		h, ok := cache[el.Source]
		if !ok {
			var err error
			if h, err = read(ctx, el.Source, since); err != nil {
				return nil, err
			}
			cache[el.Source] = h
		}
		elements[i].Hours = h
	}
	return elements, nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, window := e.pass.Now, e.pass.WindowStart
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

	rows, problem := list(control, "P-01", false)
	if !problem.IsZero() {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-05", "EV-06", "EV-07", "EV-09", "EV-10"} {
			put(id, gap(problem))
		}
		return results, nil
	}
	platform := ParsePlatform(rows)
	carrier := false
	if !platform.Runs(agent.Name) {
		if slices.ContainsFunc(platform.Machines, e.fleet.Has) || !scope.Carrier(agent.ID) {
			return OutOfScope(control, catalog.Says("mps1.not_platform"), e.decisions, agent.ID), nil
		}
		carrier = true
	}
	onPlatform := func(judge func() verdict.Judgement) verdict.Judgement {
		if carrier {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps1.no_platform_machine"))
		}
		return judge()
	}

	put("EV-01", func() verdict.Judgement {
		hours, problem := opmon1.Whole(policy, agent.ID, control, "P-10", "param.not_hours")
		if !problem.IsZero() {
			return gap(problem)
		}
		elements, err := Activity(ctx, e.facts.SourceActivity, e.hours, platform.Sources, now.Add(-7*24*time.Hour))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return mpcom1.JudgeEV01(elements, hours, now)
	}())

	filters, filtersProblem := list(control, "P-03", false)
	for id, filter := range map[string]string{"EV-02": Antispam, "EV-03": Antimalware, "EV-05": MobileCode} {
		switch {
		case e.managerErr != nil:
			put(id, passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error())))
		case !filtersProblem.IsZero():
			put(id, gap(filtersProblem))
		default:
			put(id, mpcom3.JudgeAttack(e.manager, filters, filter))
		}
	}

	settings := opacc6.Settings{}
	if s, ok := e.configs[agent.ID]; ok {
		files, err := e.facts.ConfigFiles(ctx, agent.ID, s.RecordsRun(), e.pass.LookbackStart)
		if err != nil {
			return nil, fmt.Errorf("config files: %w", err)
		}
		settings = opacc6.Settings{Snapshot: &s, Files: files}
	}
	put("EV-06", onPlatform(func() verdict.Judgement { return JudgeEV06(settings) }))

	put("EV-07", func() verdict.Judgement {
		rows, problem := list(control, "P-02", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		var domains []Domain
		for _, r := range rows {
			c := cells(r, 3)
			d, err := e.domain(ctx, c[0], c[1])
			if err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("mps1.dns", "domain", c[0], "error", err.Error()))
			}
			domains = append(domains, d)
		}
		return JudgeEV07(domains)
	}())

	put("EV-09", onPlatform(func() verdict.Judgement {
		rows, problem := list(control, "P-09", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		var paths []string
		for _, r := range rows {
			if p := cells(r, 1)[0]; filepath.IsAbs(p) {
				paths = append(paths, filepath.Clean(p))
			}
		}
		requests, problem := list(opexp5.Control, opexp5.RegisterParam, true)
		if !problem.IsZero() {
			return gap(problem)
		}
		fim, err := e.facts.FIMChanges(ctx, agent.ID, window)
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return mpcom3.JudgeEV10(fim, paths, opexp5.ParseRegister(requests), agent.Name, window)
	}))

	put("EV-10", func() verdict.Judgement {
		rows, problem := list(control, "P-07", false)
		days, daysProblem := opmon1.Whole(policy, agent.ID, control, "P-08", "param.not_days")
		j, _ := passes.Review(rows, problem, "P-07", days, daysProblem, "P-08", now)
		return j
	}())

	return results, nil
}

// domain reads what DNS publishes of a domain once a pass.
func (e *Evaluator) domain(ctx context.Context, name, selector string) (Domain, error) {
	key := name + "|" + selector
	if d, ok := e.domains[key]; ok {
		return d, nil
	}
	d := Domain{Name: name, Selector: selector}
	var err error
	if d.SPF, err = e.facts.TXT(ctx, name); err != nil {
		return d, err
	}
	if d.DMARC, err = e.facts.TXT(ctx, "_dmarc."+name); err != nil {
		return d, err
	}
	if selector != "" {
		if d.DKIM, err = e.facts.TXT(ctx, selector+"._domainkey."+name); err != nil {
			return d, err
		}
	}
	e.domains[key] = d
	return d, nil
}

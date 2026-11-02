package mpcom3

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp10"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	RuleHours(ctx context.Context, rules []string, since time.Time) (map[string][]time.Time, error)
	Networks(ctx context.Context, tools []string) (map[string]*source.Network, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
}

const control = "mp.com.3"

const algorithmsControl, algorithmsParam = "op.exp.10", "P-03"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	configs    map[string]fact.ConfigSnapshot
	networks   map[string]*source.Network
	attacks    map[string]map[string][]time.Time
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.attacks = map[string]map[string][]time.Time{}
	e.manager, e.managerErr = e.facts.Manager(ctx)
	var err error
	if e.configs, err = e.facts.ConfigSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if e.networks, err = e.facts.Networks(ctx, mpcom1.TunnelTools); err != nil {
		return fmt.Errorf("networks: %w", err)
	}
	return nil
}

func (e *Evaluator) attackHours(ctx context.Context, rules []string) (map[string][]time.Time, error) {
	key := fmt.Sprint(rules)
	if h, ok := e.attacks[key]; ok {
		return h, nil
	}
	h, err := e.facts.RuleHours(ctx, rules, e.pass.WindowStart)
	if err != nil {
		return nil, err
	}
	e.attacks[key] = h
	return h, nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	gap := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }
	list := func(controlID, id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, controlID, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			label := id
			if controlID != control {
				label = controlID + " " + id
			}
			return nil, passes.Param(label, err)
		}
		return rows, catalog.Message{}
	}

	settings := opacc6.Settings{}
	if s, ok := e.configs[agent.ID]; ok {
		files, err := e.facts.ConfigFiles(ctx, agent.ID, s.RecordsRun(), since)
		if err != nil {
			return nil, fmt.Errorf("config files: %w", err)
		}
		settings = opacc6.Settings{Snapshot: &s, Files: files}
	}
	logins, err := e.facts.Logins(ctx, agent.ID, window)
	if err != nil {
		return nil, fmt.Errorf("logins: %w", err)
	}

	put("EV-01", JudgeEV01(settings))

	algorithms, problem := list(algorithmsControl, algorithmsParam, false)
	put("EV-02", opexp10.JudgeEV03(settings, opexp10.Algorithms(algorithms), problem))
	put("EV-03", opexp10.JudgeEV04(logins, opexp10.Algorithms(algorithms), problem))

	patterns, patternsProblem := list(control, "P-02", false)
	for i, attack := range Attacks {
		id := fmt.Sprintf("EV-%02d", 4+i)
		switch {
		case e.managerErr != nil:
			put(id, passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error())))
		case !patternsProblem.IsZero():
			put(id, gap(patternsProblem))
		default:
			put(id, JudgeAttack(e.manager, patterns, attack))
		}
	}

	put("EV-07", func() verdict.Judgement {
		if e.managerErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error()))
		}
		if !patternsProblem.IsZero() {
			return gap(patternsProblem)
		}
		hours, err := e.attackHours(ctx, RuleIDs(e.manager, patterns))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		rows, problem := list(opexp7.Control, opexp7.RegisterParam, true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV07(hours[agent.ID], opexp7.Of(opexp7.ParseRegister(rows), agent.Name, now))
	}())

	put("EV-08", func() verdict.Judgement {
		rows, problem := list(control, "P-05", true)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV08(rows, agent.Name, e.networks[agent.ID])
	}())

	put("EV-10", func() verdict.Judgement {
		rows, problem := list(control, "P-06", false)
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
		return JudgeEV10(fim, paths, opexp5.ParseRegister(requests), agent.Name, window)
	}())

	put("EV-11", func() verdict.Judgement {
		rows, problem := list(control, "P-07", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		return JudgeEV11(rows, now)
	}())

	return results, nil
}

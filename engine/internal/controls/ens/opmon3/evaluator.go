package opmon3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Manager(ctx context.Context) (*source.Manager, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	LocationDetections(ctx context.Context, since time.Time) (map[string]map[string]time.Time, error)
	GroupDetections(ctx context.Context, groups []string, since time.Time) (source.Detection, error)
	SCASummaries(ctx context.Context, since time.Time) (map[string][]source.SCASummary, error)
	PackageCounts(ctx context.Context) (map[string]int, error)
}

const control = "op.mon.3"

// Sources are read back a week: P-01 hours stop there.
const sourcesHorizon = 7 * 24 * time.Hour

// SCA results are raised only when they change: the newest is current however old.
const scaHorizon = 366 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	manager    *source.Manager
	managerErr error
	reporting  map[string]source.Reporting
	wazuh      map[string]fact.WazuhAgentConfig
	locations  map[string]map[string]time.Time
	network    source.Detection
	sca        map[string][]source.SCASummary
	packages   map[string]int
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.manager, e.managerErr = e.facts.Manager(ctx)

	var err error
	steps := []struct {
		name string
		do   func() error
	}{
		{"reporting", func() (err error) { e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); return }},
		{"locations", func() (err error) {
			e.locations, err = e.facts.LocationDetections(ctx, pass.Now.Add(-sourcesHorizon))
			return
		}},
		{"network", func() (err error) {
			e.network, err = e.facts.GroupDetections(ctx, opmon1.NetworkGroups, pass.Now.Add(-opmon1.Horizon))
			return
		}},
		{"sca", func() (err error) { e.sca, err = e.facts.SCASummaries(ctx, pass.Now.Add(-scaHorizon)); return }},
		{"packages", func() (err error) { e.packages, err = e.facts.PackageCounts(ctx); return }},
	}
	for _, s := range steps {
		if err = s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	fromManager := func(judge func(m *source.Manager) verdict.Judgement) verdict.Judgement {
		if e.managerErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.manager_unread", "error", e.managerErr.Error()))
		}
		return judge(e.manager)
	}
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	var reporting *source.Reporting
	if r, ok := e.reporting[agent.ID]; ok {
		reporting = &r
	}
	var config *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		config = &c
	}

	put("EV-01", fromManager(func(m *source.Manager) verdict.Judgement {
		hours, problem := opmon1.Whole(policy, agent.ID, control, "P-03", "param.not_hours")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV01(m, reporting, hours, now)
	}))

	put("EV-02", func() verdict.Judgement {
		rows, problem := list("P-01", false)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV02(Sources(rows, agent.Name), config, e.locations[agent.ID], now)
	}())

	put("EV-03", fromManager(func(m *source.Manager) verdict.Judgement {
		sets, problem := list("P-02", true)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV03(m, sets)
	}))

	surface := Surface{SCAResults: len(e.sca[agent.ID]), Packages: e.packages[agent.ID]}
	if config != nil {
		surface.SCAEnabled = config.Status == fact.SourceRead && !config.SCADisabled
	}
	if e.managerErr == nil {
		surface.Detector = e.manager.Vulnerability
		// Wazuh leaves the manager's own inventory out of the state indices; its API holds it.
		if agent.ID == source.ManagerID && e.manager.Version != "" {
			surface.Packages = max(surface.Packages, 1)
		}
	}

	put("EV-04", fromManager(func(*source.Manager) verdict.Judgement { return JudgeEV04(surface) }))

	put("EV-06", func() verdict.Judgement {
		probes, problem := list("P-05", true)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV06(probes, e.network, now)
	}())

	put("EV-08", fromManager(func(m *source.Manager) verdict.Judgement {
		rows, problem := list("P-07", false)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV08(m, rows)
	}))

	put("EV-09", fromManager(func(m *source.Manager) verdict.Judgement {
		rows, problem := list("P-08", false)
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV09(m, rows)
	}))

	planRows, planProblem := list("P-09", false)
	register, registerProblem := list("P-10", true)
	inspection := func(continuous bool, why catalog.Message, kind string) verdict.Judgement {
		if !planProblem.IsZero() && !continuous {
			return passes.Gap(verdict.CauseConfiguration, planProblem)
		}
		return JudgeInspection(continuous, why, register, registerProblem, kind, Plan(planRows), now)
	}

	scaContinuous := surface.SCAEnabled && surface.SCAResults > 0 && reporting != nil
	put("EV-10", inspection(scaContinuous, catalog.Says("opmon3.sca_continuous", "policies", surface.SCAResults), KindConfiguration))
	put("EV-11", inspection(surface.Detector && surface.Packages > 0 && reporting != nil, catalog.Says("opmon3.vulnerabilities_continuous", "packages", surface.Packages), KindVulnerabilities))
	put("EV-12", inspection(false, catalog.Message{}, KindPentest))

	return results, nil
}

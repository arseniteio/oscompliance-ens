package opexp7

import (
	"context"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp6"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	MalwareProtections(ctx context.Context, since time.Time) (map[string]fact.MalwareProtection, error)
	AlertHours(ctx context.Context, minLevel int, excluded []string, since time.Time) (map[string][]source.AlertHour, error)
	ActiveResponseTimes(ctx context.Context, since time.Time) (map[string][]time.Time, error)
}

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	wazuh      map[string]fact.WazuhAgentConfig
	protection map[string]fact.MalwareProtection
	responses  map[string][]time.Time
	alerts     map[string]map[string][]source.AlertHour
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return Control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.alerts = map[string]map[string][]source.AlertHour{}
	steps := []struct {
		name string
		do   func() error
	}{
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); return }},
		{"protection", func() (err error) { e.protection, err = e.facts.MalwareProtections(ctx, pass.WindowStart); return }},
		{"active responses", func() (err error) {
			e.responses, err = e.facts.ActiveResponseTimes(ctx, pass.Now.Add(-Horizon))
			return
		}},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

// hoursFor reads the alert hours of the fleet once per pass for each level and exclusion asked.
func (e *Evaluator) hoursFor(ctx context.Context, level int, excluded []string) (map[string][]source.AlertHour, error) {
	key := fmt.Sprint(level, excluded)
	if h, ok := e.alerts[key]; ok {
		return h, nil
	}
	h, err := e.facts.AlertHours(ctx, level, excluded, e.pass.WindowStart)
	if err == nil {
		e.alerts[key] = h
	}
	return h, err
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	rows, err := policy.List(agent.ID, Control, RegisterParam)
	registerProblem := problemOf(RegisterParam, err)
	incidents := Of(ParseRegister(rows), agent.Name, now)

	classRows, err := policy.List(agent.ID, Control, "P-01")
	classes, classProblem := ParseClasses(classRows)
	if err != nil {
		classProblem = passes.Param("P-01", err)
	}

	excluded, _ := policy.ListColumn(agent.ID, Control, "P-12", 0)
	var hours []source.AlertHour
	if classProblem.IsZero() {
		fleet, err := e.hoursFor(ctx, MinLevel(classes), excluded)
		if err != nil {
			return results, fmt.Errorf("alert hours: %w", err)
		}
		hours = fleet[agent.ID]
	}

	put("EV-01", JudgeEV01(hours, classes, classProblem))

	escalation, err := policy.List(agent.ID, Control, "P-02")
	escalationProblem := first(registerProblem, classProblem, problemOf("P-02", err))
	put("EV-02", JudgeEV02(hours, classes, escalation, incidents, agent.Name, escalationProblem))

	deadlines, err := policy.List(agent.ID, Control, "P-05")
	put("EV-03", JudgeEV03(incidents, deadlines, first(registerProblem, problemOf("P-05", err)), now))

	owners, err := policy.List(agent.ID, Control, "P-04")
	put("EV-04", JudgeEV04(incidents, escalation, owners, first(escalationProblem, problemOf("P-04", err))))

	var manager *fact.WazuhAgentConfig
	if m, ok := e.wazuh[source.ManagerID]; ok {
		manager = &m
	}
	put("EV-05", gated(registerProblem, func() verdict.Judgement { return JudgeEV05(incidents, manager, now) }))
	put("EV-06", gated(registerProblem, func() verdict.Judgement { return JudgeEV06(incidents, e.responses[agent.ID], now) }))

	personal, err := policy.List(agent.ID, Control, "P-07")
	put("EV-07", JudgeEV07(incidents, personal, first(registerProblem, problemOf("P-07", err))))

	put("EV-08", JudgeEV08(incidents, classes, first(registerProblem, classProblem)))
	put("EV-09", gated(registerProblem, func() verdict.Judgement { return JudgeEV09(incidents, e.responses[agent.ID], now) }))

	advisories, err := policy.List(agent.ID, Control, "P-11")
	put("EV-10", JudgeEV10(manager, advisories, problemOf("P-11", err), now))

	var c *fact.WazuhAgentConfig
	if x, ok := e.wazuh[agent.ID]; ok {
		c = &x
	}
	var p *fact.MalwareProtection
	if x, ok := e.protection[agent.ID]; ok {
		p = &x
	}
	put("EV-11", opexp6.JudgeEV11(true, c, p))

	put("EV-12", gated(registerProblem, func() verdict.Judgement { return JudgeEV12(incidents) }))

	return results, nil
}

func gated(problem catalog.Message, j func() verdict.Judgement) verdict.Judgement {
	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	return j()
}

func first(problems ...catalog.Message) catalog.Message {
	for _, p := range problems {
		if !p.IsZero() {
			return p
		}
	}
	return catalog.Message{}
}

func problemOf(id string, err error) catalog.Message {
	if err != nil {
		return passes.Param(id, err)
	}
	return catalog.Message{}
}

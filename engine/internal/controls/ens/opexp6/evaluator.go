package opexp6

import (
	"context"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	MalwareProtections(ctx context.Context, since time.Time) (map[string]fact.MalwareProtection, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	RuleCounts(ctx context.Context, rules []string, field string, since time.Time) (map[string][]source.AlertCount, error)
}

const control = "op.exp.6"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	protection map[string]fact.MalwareProtection
	wazuh      map[string]fact.WazuhAgentConfig
	clamav     map[string][]source.AlertCount
	virustotal map[string][]source.AlertCount
	usb        map[string][]source.AlertCount
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	w := pass.WindowStart

	steps := []struct {
		name string
		do   func() error
	}{
		{"protection", func() (err error) { e.protection, err = e.facts.MalwareProtections(ctx, w); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"clamav", func() (err error) {
			e.clamav, err = e.facts.RuleCounts(ctx, []string{ruleDetection, ruleRepeated}, "data.url", w)
			return
		}},
		{"virustotal", func() (err error) {
			e.virustotal, err = e.facts.RuleCounts(ctx, []string{"87105"}, "data.virustotal.source.file", w)
			return
		}},
		{"usb", func() (err error) {
			e.usb, err = e.facts.RuleCounts(ctx, []string{"81101"}, "rule.description", w)
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

func (e *Evaluator) Agent(_ context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	var p *fact.MalwareProtection
	if x, ok := e.protection[agent.ID]; ok {
		p = &x
	}
	var c, manager *fact.WazuhAgentConfig
	if x, ok := e.wazuh[agent.ID]; ok {
		c = &x
	}
	if x, ok := e.wazuh[source.ManagerID]; ok {
		manager = &x
	}

	expected, err := policy.List(agent.ID, control, "P-02")
	put("EV-01", JudgeEV01(p, expected, passes.ParamProblem("P-02", err)))

	hours, problem := passes.Whole(policy, agent.ID, control, "P-03", "param.not_hours")
	put("EV-02", JudgeEV02(p, hours, problem, now))

	settings, err := policy.List(agent.ID, control, "P-04")
	put("EV-03", JudgeEV03(p, settings, passes.ParamProblem("P-04", err)))

	put("EV-04", JudgeEV04(p, e.clamav[agent.ID]))

	days, problem := passes.Whole(policy, agent.ID, control, "P-06", "param.not_days")
	put("EV-05", JudgeEV05(p, days, problem, now))

	paths, err := policy.List(agent.ID, control, "P-07")
	put("EV-06", JudgeEV06(c, paths, passes.ParamProblem("P-07", err)))

	put("EV-07", JudgeEV07(p))

	rows, err := policy.List(agent.ID, control, "P-09")
	if err != nil {
		gap := passes.Gap(verdict.CauseConfiguration, passes.Param("P-09", err))
		for _, id := range []string{"EV-08", "EV-09", "EV-10", "EV-11"} {
			put(id, gap)
		}
	} else {
		on := Capabilities(rows)
		put("EV-08", JudgeEV08(on["virustotal"], manager, c, e.virustotal[agent.ID]))
		put("EV-09", JudgeEV09(on["yara"], p))
		put("EV-10", JudgeEV10(on["rootcheck"], c))
		put("EV-11", JudgeEV11(on["active_response"], c, p))
	}

	usb, err := policy.List(agent.ID, control, "P-10")
	value := ""
	if len(usb) > 0 {
		value = usb[0]
	}
	put("EV-12", JudgeEV12(value, passes.ParamProblem("P-10", err), e.usb[agent.ID], p))

	return results, nil
}

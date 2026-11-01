package opnub1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	GroupDetections(ctx context.Context, groups []string, since time.Time) (source.Detection, error)
	CloudAdminOperations(ctx context.Context, since time.Time) ([]source.CloudOperation, error)
}

const control = "op.nub.1"

// Cloud logs are read back a week: P-13 stops there.
const logsHorizon = 7 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	logs       map[string]source.Detection
	operations []source.CloudOperation
	decisions  map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}
	e.logs = map[string]source.Detection{}

	for module, groups := range ModuleGroups {
		d, err := e.facts.GroupDetections(ctx, groups, pass.Now.Add(-logsHorizon))
		if err != nil {
			return fmt.Errorf("%s logs: %w", module, err)
		}
		e.logs[module] = d
	}
	var err error
	if e.operations, err = e.facts.CloudAdminOperations(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("cloud operations: %w", err)
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
	list := func(id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, control, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}
	gap := func(problems ...catalog.Message) (verdict.Judgement, bool) {
		for _, p := range problems {
			if !p.IsZero() {
				return passes.Gap(verdict.CauseConfiguration, p), true
			}
		}
		return verdict.Judgement{}, false
	}

	position, problem := list("P-01", false)
	if j, bad := gap(problem); bad {
		for _, id := range []string{"EV-01", "EV-04", "EV-08", "EV-09"} {
			put(id, j)
		}
		return results, nil
	}
	if c, ok := catalog.LookupControl(control); ok {
		var ids []string
		for _, r := range c.Requirements {
			ids = append(ids, r.ID)
		}
		e.decisions[agent.ID] = Decisions(position[0], ids)
	}
	if p := key(position[0]); p != User && p != Both {
		out := verdict.Explain(verdict.NotApplicable, "", catalog.Says("opnub1.position", "position", p))
		for _, id := range []string{"EV-01", "EV-04", "EV-08", "EV-09"} {
			put(id, out)
		}
		return results, nil
	}

	inventory, inventoryProblem := list("P-02", false)
	used := Used(inventory)
	integrationRows, integrationsProblem := list("P-06", false)
	integrations := Integrations(integrationRows)

	put("EV-01", func() verdict.Judgement {
		hours, hoursProblem := opmon1.Whole(policy, agent.ID, control, "P-13", "param.not_hours")
		if j, bad := gap(integrationsProblem, hoursProblem); bad {
			return j
		}
		return JudgeEV01(integrations, e.logs, hours, now)
	}())

	put("EV-04", func() verdict.Judgement {
		admins, problem := list("P-11", true)
		if j, bad := gap(integrationsProblem, problem); bad {
			return j
		}
		return JudgeEV04(integrations, e.operations, admins)
	}())

	put("EV-08", func() verdict.Judgement {
		certifications, problem := list("P-04", true)
		if j, bad := gap(inventoryProblem, problem); bad {
			return j
		}
		return JudgeEV08(used, certifications, now)
	}())

	put("EV-09", func() verdict.Judgement {
		var r Record
		var problems []catalog.Message
		for _, p := range []struct {
			id   string
			rows *[]string
		}{{"P-03", &r.Conformity}, {"P-08", &r.Jurisdiction}, {"P-09", &r.Encryption}, {"P-10", &r.Pentests}} {
			var problem catalog.Message
			*p.rows, problem = list(p.id, true)
			problems = append(problems, problem)
		}
		months, monthsProblem := opmon1.Whole(policy, agent.ID, control, "P-12", "param.not_months")
		r.PentestMonths = months
		if j, bad := gap(append(problems, inventoryProblem, monthsProblem)...); bad {
			return j
		}
		return JudgeEV09(used, r, now)
	}())

	return results, nil
}

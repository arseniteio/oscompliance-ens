package mpinfo6

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	BackupSnapshots(ctx context.Context, since time.Time) (map[string]fact.BackupSnapshot, error)
}

const control = "mp.info.6"

var evidences = []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-06"}

type Evaluator struct {
	facts Facts

	pass      evaluator.Pass
	backups   map[string]fact.BackupSnapshot
	decisions map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}
	var err error
	if e.backups, err = e.facts.BackupSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("backups: %w", err)
	}
	return nil
}

// Decisions leave out the machines that declare no copies: mp.info.6 is measured where copies are made
// or kept.
func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	all := func(j verdict.Judgement) {
		for _, id := range evidences {
			put(id, j)
		}
	}

	rows, err := policy.List(agent.ID, control, "P-04")
	if errors.Is(err, params.ErrNotSet) {
		out := verdict.Explain(verdict.NotApplicable, "", catalog.Says("mpinfo6.out_of_scope"))
		all(out)
		e.decisions[agent.ID] = map[string]verdict.Judgement{}
		if c, ok := catalog.LookupControl(control); ok {
			for _, r := range c.Requirements {
				e.decisions[agent.ID][r.ID] = out
			}
		}
		return results, nil
	}
	copies := ParseCopies(rows)
	if err == nil && len(copies) == 0 {
		err = errors.New("no absolute path")
	}
	if err != nil {
		all(passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", err)))
		return results, nil
	}

	var b *fact.BackupSnapshot
	if s, ok := e.backups[agent.ID]; ok {
		b = &s
	}
	read, gap, ok := Read(b, copies)

	tests, testsErr := policy.List(agent.ID, control, "P-06")
	maxDays, daysProblem := whole(policy, agent.ID, "P-05", "param.not_days")
	j, _ := passes.Review(Restores(tests, agent.Name), problemOf("P-06", testsErr), "P-06", maxDays, daysProblem, "P-05", now)
	put("EV-05", j)

	if !ok {
		for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-06"} {
			put(id, gap)
		}
		return results, nil
	}

	put("EV-01", JudgeEV01(copies, read))

	put("EV-02", func() verdict.Judgement {
		hours, problem := optional(policy, agent.ID, "P-01", "param.not_hours")
		margin, marginProblem := optional(policy, agent.ID, "P-02", "param.not_hours")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		if !marginProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, marginProblem)
		}
		return JudgeEV02(copies, read, hours, margin, now)
	}())

	put("EV-03", func() verdict.Judgement {
		days, problem := optional(policy, agent.ID, "P-03", "param.not_days")
		if !problem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, problem)
		}
		return JudgeEV03(copies, read, days, now)
	}())

	put("EV-04", func() verdict.Judgement {
		allowed, err := policy.List(agent.ID, control, "P-07")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-07", err))
		}
		keys, _ := policy.List(agent.ID, control, "P-08")
		return JudgeEV04(copies, read, b.KeyFiles, keyPaths(keys), allowed)
	}())

	put("EV-06", JudgeEV06(copies, read))

	return results, nil
}

func keyPaths(rows []string) []string {
	var out []string
	for _, r := range rows {
		if p := strings.TrimSpace(strings.Split(r, "|")[0]); filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
		}
	}
	return out
}

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

// optional is a whole number of P-01, P-02 or P-03, 0 when it is not set: a copy can carry its own.
func optional(policy params.Lister, agentID, id, notWhole string) (int, catalog.Message) {
	v, err := policy.Number(agentID, control, id)
	switch {
	case errors.Is(err, params.ErrNotSet):
		return 0, catalog.Message{}
	case err != nil:
		return 0, passes.Param(id, err)
	case v < 0 || v != float64(int(v)):
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

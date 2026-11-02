package opexp5

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp4"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	FleetReporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
	TransactionSnapshots(ctx context.Context, since time.Time) (map[string]fact.TransactionSnapshot, error)
	PackageTransactions(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PackageTransaction, error)
	UnitSnapshots(ctx context.Context, since time.Time) (map[string]fact.UnitSnapshot, error)
	SnapshotLists(ctx context.Context, since time.Time) (map[string]fact.SnapshotList, error)
	InstalledVersions(ctx context.Context, ids []string, since time.Time) (map[string]map[string]time.Time, error)
	PackageVersions(ctx context.Context, ids []string) (map[string]map[string]bool, error)
}

const preproductionHorizon = 90 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass         evaluator.Pass
	wazuh        map[string]fact.WazuhAgentConfig
	transactions map[string]fact.TransactionSnapshot
	units        map[string]fact.UnitSnapshot
	snapshots    map[string]fact.SnapshotList
	ids          map[string]string
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return Control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	w := pass.WindowStart
	var reporting map[string]source.Reporting

	steps := []struct {
		name string
		do   func() error
	}{
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"monitoring", func() (err error) { reporting, err = e.facts.FleetReporting(ctx, pass.LookbackStart); return }},
		{"transactions", func() (err error) { e.transactions, err = e.facts.TransactionSnapshots(ctx, w); return }},
		{"units", func() (err error) { e.units, err = e.facts.UnitSnapshots(ctx, w); return }},
		{"snapshots", func() (err error) { e.snapshots, err = e.facts.SnapshotLists(ctx, w); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	e.ids = map[string]string{}
	for id, r := range reporting {
		if r.Name != "" {
			e.ids[strings.ToLower(r.Name)] = id
		}
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	var errs []error

	fim, err := e.facts.FIMChanges(ctx, agent.ID, window)
	if err != nil {
		errs = append(errs, fmt.Errorf("fim: %w", err))
	}
	var history *fact.TransactionSnapshot
	var records []fact.PackageTransaction
	if s, ok := e.transactions[agent.ID]; ok {
		history = &s
		if records, err = e.facts.PackageTransactions(ctx, agent.ID, s.RecordsRun(), since); err != nil {
			errs = append(errs, fmt.Errorf("transactions: %w", err))
		}
	}
	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}
	changes := Changes(fim, records, window)

	rows, err := policy.List(agent.ID, Control, RegisterParam)
	requests, registerProblem := ParseRegister(rows), passes.ParamProblem(RegisterParam, err)

	var config *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		config = &c
	}
	put("EV-01", JudgeEV01(config, history, changes))
	put("EV-02", JudgeEV02(changes, requests, registerProblem, agent.Name))

	put("EV-03", func() verdict.Judgement {
		required, err := policy.List(agent.ID, Control, "P-02")
		problem := registerProblem
		if err != nil && problem.IsZero() {
			problem = passes.Param("P-02", err)
		}
		prefix := ""
		if system, err := policy.List(agent.ID, Control, "P-01"); err == nil && len(system) > 0 {
			c := strings.Split(system[0], "|")
			if len(c) >= 3 {
				prefix = strings.TrimSpace(c[2])
			}
		}
		return JudgeEV03(requests, agent.Name, required, prefix, policy.Level() == "ALTO", problem, now)
	}())

	put("EV-04", func() verdict.Judgement {
		managers, err := policy.ListColumn(agent.ID, Control, "P-04", 1)
		problem := registerProblem
		if err != nil && problem.IsZero() {
			problem = passes.Param("P-04", err)
		}
		return JudgeEV04(requests, agent.Name, managers, problem, now)
	}())

	put("EV-05", func() verdict.Judgement {
		pairs, err := policy.List(agent.ID, "op.exp.4", "P-06")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("op.exp.4 P-06", err))
		}
		preprod := opexp4.PreproductionOf(pairs, agent.Name)
		if preprod == "" {
			return opexp4.JudgeEV08(agent.Name, pairs, catalog.Message{}, nil, nil, nil, window)
		}
		preprodID, known := e.ids[strings.ToLower(preprod)]
		if !known {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.preproduction_unknown", "preprod", preprod))
		}
		installed, err := e.facts.InstalledVersions(ctx, []string{agent.ID, preprodID}, now.Add(-preproductionHorizon))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		present, err := e.facts.PackageVersions(ctx, []string{preprodID})
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		return opexp4.JudgeEV08(agent.Name, pairs, catalog.Message{}, installed[agent.ID], installed[preprodID], present[preprodID], window)
	}())

	put("EV-06", func() verdict.Judgement {
		docs, err := policy.List(agent.ID, Control, "P-06")
		problem := registerProblem
		if err != nil && problem.IsZero() {
			problem = passes.Param("P-06", err)
		}
		return JudgeEV06(requests, agent.Name, documents(docs), problem, now)
	}())

	put("EV-07", func() verdict.Judgement {
		var units *fact.UnitSnapshot
		if u, ok := e.units[agent.ID]; ok {
			units = &u
		}
		hours, problem := passes.Whole(policy, agent.ID, Control, "P-09", "param.not_hours")
		if problem.IsZero() {
			problem = registerProblem
		}
		return JudgeEV07(units, changes, requests, agent.Name, hours, problem, now)
	}())

	put("EV-09", func() verdict.Judgement {
		rows, err := policy.List(agent.ID, "op.exp.4", "P-07")
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("op.exp.4 P-07", err))
		}
		hours, ok := opexp4.ReversionHours(rows, agent.Name)
		if !ok {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.no_reversion_row", "machine", agent.Name))
		}
		var snapshots *fact.SnapshotList
		if s, ok := e.snapshots[agent.ID]; ok {
			snapshots = &s
		}
		return JudgeEV09(changes, snapshots, hours, catalog.Message{})
	}())

	return results, nil
}

func documents(rows []string) []Document {
	var out []Document
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		days, err := strconv.Atoi(strings.TrimSpace(c[2]))
		if err != nil || days < 0 {
			days = 0
		}
		if name := strings.TrimSpace(c[0]); name != "" {
			out = append(out, Document{Name: name, Days: days})
		}
	}
	return out
}

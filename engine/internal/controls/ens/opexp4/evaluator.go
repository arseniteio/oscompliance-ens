package opexp4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp1"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	Inventories(ctx context.Context) (map[string]*source.Inventory, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	Vulnerabilities(ctx context.Context) (map[string][]source.VulnerabilityDay, error)
	Vendors(ctx context.Context) (map[string][]string, error)
	UpdateStatuses(ctx context.Context, since time.Time) (map[string]fact.UpdateStatus, error)
	TransactionSnapshots(ctx context.Context, since time.Time) (map[string]fact.TransactionSnapshot, error)
	PackageTransactions(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PackageTransaction, error)
	SnapshotLists(ctx context.Context, since time.Time) (map[string]fact.SnapshotList, error)
	InstalledVersions(ctx context.Context, ids []string, since time.Time) (map[string]map[string]time.Time, error)
	PackageVersions(ctx context.Context, ids []string) (map[string]map[string]bool, error)
}

const control = "op.exp.4"

// A version reached pre-production at most this long before it reached production.
const preproductionHorizon = 90 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass         evaluator.Pass
	inventories  map[string]*source.Inventory
	reporting    map[string]source.Reporting
	wazuh        map[string]fact.WazuhAgentConfig
	vulns        map[string][]source.VulnerabilityDay
	vendors      map[string][]string
	updates      map[string]fact.UpdateStatus
	transactions map[string]fact.TransactionSnapshot
	snapshots    map[string]fact.SnapshotList
	ids          map[string]string
	installed    map[string]map[string]time.Time
	present      map[string]map[string]bool
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
		{"inventory", func() (err error) { e.inventories, err = e.facts.Inventories(ctx); return }},
		{"monitoring", func() (err error) { e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"vulnerabilities", func() (err error) { e.vulns, err = e.facts.Vulnerabilities(ctx); return }},
		{"vendors", func() (err error) { e.vendors, err = e.facts.Vendors(ctx); return }},
		{"updates", func() (err error) { e.updates, err = e.facts.UpdateStatuses(ctx, w); return }},
		{"transactions", func() (err error) { e.transactions, err = e.facts.TransactionSnapshots(ctx, w); return }},
		{"snapshots", func() (err error) { e.snapshots, err = e.facts.SnapshotLists(ctx, w); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	e.ids = map[string]string{}
	for id, r := range e.reporting {
		if r.Name != "" {
			e.ids[strings.ToLower(r.Name)] = id
		}
	}
	e.installed, e.present = map[string]map[string]time.Time{}, map[string]map[string]bool{}
	return nil
}

// versions reads, once per pass, the versions installed on a machine and present there now.
func (e *Evaluator) versions(ctx context.Context, id string) (map[string]time.Time, map[string]bool, error) {
	if _, ok := e.installed[id]; !ok {
		installed, err := e.facts.InstalledVersions(ctx, []string{id}, e.pass.Now.Add(-preproductionHorizon))
		if err != nil {
			return nil, nil, err
		}
		present, err := e.facts.PackageVersions(ctx, []string{id})
		if err != nil {
			return nil, nil, err
		}
		e.installed[id], e.present[id] = installed[id], present[id]
	}
	return e.installed[id], e.present[id], nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart
	manager := agent.ID == source.ManagerID
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	inv := e.inventories[agent.ID]

	freshness := opexp1.Freshness{Manager: manager, Now: now}
	freshness.MaxHours, freshness.HoursProblem = whole(policy, agent.ID, "op.exp.1", "P-08", "param.not_hours")
	if c, ok := e.wazuh[agent.ID]; ok {
		freshness.Config = &c
	}
	if r, ok := e.reporting[agent.ID]; ok {
		freshness.Reporting = &r
	}
	put("EV-01", JudgeEV01(opexp1.JudgeEV02(inv, freshness), manager, e.vulns[agent.ID]))

	rows, err := policy.List(agent.ID, control, "P-01")
	deadlines, problem := Deadlines(rows)
	if err != nil {
		problem = passes.Param("P-01", err)
	}
	put("EV-02", JudgeEV02(manager, e.vulns[agent.ID], deadlines, problem, now))

	var updates *fact.UpdateStatus
	if u, ok := e.updates[agent.ID]; ok {
		updates = &u
	}
	listDays, listProblem := whole(policy, agent.ID, control, "P-10", "param.not_days")
	put("EV-03", JudgeEV03(updates, listDays, listProblem, now))

	transactions := Transactions{}
	var errs []error
	if s, ok := e.transactions[agent.ID]; ok {
		records, err := e.facts.PackageTransactions(ctx, agent.ID, s.RecordsRun(), since)
		if err != nil {
			errs = append(errs, fmt.Errorf("transactions: %w", err))
		}
		transactions = Transactions{Snapshot: &s, Records: records}
	}

	authorised, err := policy.List(agent.ID, control, "P-02")
	put("EV-04", JudgeEV04(transactions, window, authorised, problemOf("P-02", err)))

	var system *source.System
	if inv != nil {
		system = inv.System
	}
	eol, err := policy.List(agent.ID, control, "P-05")
	put("EV-05", JudgeEV05(system, eol, problemOf("P-05", err), now))

	sources, err := policy.List(agent.ID, control, "P-03")
	vendors := e.vendors[agent.ID]
	if len(vendors) == 0 && inv != nil {
		vendors = inv.Vendors
	}
	put("EV-06", JudgeEV06(vendors, sources, problemOf("P-03", err)))

	windows, err := policy.List(agent.ID, control, "P-04")
	put("EV-07", JudgeEV07(transactions, window, windows, agent.Name, problemOf("P-04", err)))

	pairs, err := policy.List(agent.ID, control, "P-06")
	ev08 := func() verdict.Judgement {
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-06", err))
		}
		preprod := PreproductionOf(pairs, agent.Name)
		preprodID, known := e.ids[strings.ToLower(preprod)]
		if preprod != "" && !known {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.preproduction_unknown", "preprod", preprod))
		}
		installed, _, err := e.versions(ctx, agent.ID)
		if err != nil {
			errs = append(errs, fmt.Errorf("installed versions: %w", err))
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		var preInstalled map[string]time.Time
		var preNow map[string]bool
		if preprodID != "" {
			if preInstalled, preNow, err = e.versions(ctx, preprodID); err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
			}
		}
		return JudgeEV08(agent.Name, pairs, catalog.Message{}, installed, preInstalled, preNow, window)
	}
	put("EV-08", ev08())

	reversion, err := policy.List(agent.ID, control, "P-07")
	ev09 := func() verdict.Judgement {
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-07", err))
		}
		hours, ok := ReversionHours(reversion, agent.Name)
		if !ok {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.no_reversion_row", "machine", agent.Name))
		}
		var snapshots *fact.SnapshotList
		if s, ok := e.snapshots[agent.ID]; ok {
			snapshots = &s
		}
		return JudgeEV09(transactions, window, snapshots, hours, catalog.Message{})
	}
	put("EV-09", ev09())

	return results, errors.Join(errs...)
}

func whole(policy params.Lister, agentID, controlID, id, notWhole string) (int, catalog.Message) {
	v, err := policy.Number(agentID, controlID, id)
	if err != nil {
		return 0, passes.Param(id, err)
	}
	if v < 1 || v != float64(int(v)) {
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

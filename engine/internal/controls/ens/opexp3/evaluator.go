package opexp3

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc4"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp2"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp4"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/groupconf"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	SCASummaries(ctx context.Context, since time.Time) (map[string][]source.SCASummary, error)
	SCALowest(ctx context.Context, since time.Time) (map[string]map[string]int, error)
	SCARegressions(ctx context.Context, since time.Time) (map[string][]source.SCARegression, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]source.AuditAccess, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	NewPackages(ctx context.Context, since time.Time) (map[string][]string, error)
	PackageSelections(ctx context.Context, since time.Time) (map[string]fact.PackageSelection, error)
	UnitSnapshots(ctx context.Context, since time.Time) (map[string]fact.UnitSnapshot, error)
	ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error)
	ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error)
	BackupSnapshots(ctx context.Context, since time.Time) (map[string]fact.BackupSnapshot, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
	Vulnerabilities(ctx context.Context) (map[string][]source.VulnerabilityDay, error)
}

const control = "op.exp.3"

const summariesHorizon = 366 * 24 * time.Hour

// The score series and the regressions are read back this far: P-12 cannot ask for more.
const seriesHorizon = 90 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass        evaluator.Pass
	wazuh       map[string]fact.WazuhAgentConfig
	reporting   map[string]source.Reporting
	summaries   map[string][]source.SCASummary
	regressions map[string][]source.SCARegression
	watches     map[string]fact.AuditWatchSnapshot
	identities  map[string][]fact.IdentitySnapshot
	installed   map[string][]string
	selections  map[string]fact.PackageSelection
	units       map[string]fact.UnitSnapshot
	listening   map[string]fact.ListeningSnapshot
	backups     map[string]fact.BackupSnapshot
	lowest      map[int]map[string]map[string]int
	vulns       map[string][]source.VulnerabilityDay
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	w := pass.WindowStart
	e.lowest = map[int]map[string]map[string]int{}

	steps := []struct {
		name string
		do   func() error
	}{
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"monitoring", func() (err error) { e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); return }},
		{"sca", func() (err error) {
			e.summaries, err = e.facts.SCASummaries(ctx, pass.Now.Add(-summariesHorizon))
			return
		}},
		{"sca regressions", func() (err error) {
			e.regressions, err = e.facts.SCARegressions(ctx, pass.Now.Add(-seriesHorizon))
			return
		}},
		{"audit watches", func() (err error) { e.watches, err = e.facts.AuditWatchSnapshots(ctx, w); return }},
		{"identity", func() (err error) { e.identities, err = e.facts.IdentitySnapshots(ctx, w, 1); return }},
		{"new packages", func() (err error) { e.installed, err = e.facts.NewPackages(ctx, w); return }},
		{"package selection", func() (err error) { e.selections, err = e.facts.PackageSelections(ctx, w); return }},
		{"units", func() (err error) { e.units, err = e.facts.UnitSnapshots(ctx, w); return }},
		{"listening", func() (err error) { e.listening, err = e.facts.ListeningSnapshots(ctx, w); return }},
		{"backups", func() (err error) { e.backups, err = e.facts.BackupSnapshots(ctx, w); return }},
		{"vulnerabilities", func() (err error) { e.vulns, err = e.facts.Vulnerabilities(ctx); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

// lowestFor reads the score series of a number of days once per pass, whatever machines ask for it.
func (e *Evaluator) lowestFor(ctx context.Context, days int) (map[string]map[string]int, error) {
	if l, ok := e.lowest[days]; ok {
		return l, nil
	}
	l, err := e.facts.SCALowest(ctx, e.pass.Now.Add(-time.Duration(days)*24*time.Hour))
	if err == nil {
		e.lowest[days] = l
	}
	return l, err
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart

	results := map[string]evaluator.Result{}
	var errs []error
	failed := map[string]bool{}
	read := func(name string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			failed[name] = true
		}
	}
	judge := func(id string, needs []string, j func() verdict.Judgement) {
		for _, n := range needs {
			if failed[n] {
				return
			}
		}
		results[id] = evaluator.Result{Judgement: j()}
	}

	accounts := opacc4.Accounts{}
	if list, ok := e.identities[agent.ID]; ok && len(list) > 0 {
		records, err := e.facts.IdentityRecords(ctx, agent.ID, list[0].RecordsRun(), since)
		read("accounts", err)
		accounts.Identity, accounts.IdentityRecords = &list[0], records
	}
	accesses, err := e.facts.AuditAccesses(ctx, agent.ID, window)
	read("audit", err)

	var listening *fact.ListeningSnapshot
	var sockets []fact.ListeningSocket
	if s, ok := e.listening[agent.ID]; ok {
		listening = &s
		sockets, err = e.facts.ListeningSockets(ctx, agent.ID, s.RecordsRun(), since)
		read("listening", err)
	}

	days, daysProblem := whole(policy, agent.ID, control, "P-12", "param.not_days")

	judge("EV-01", nil, func() verdict.Judgement {
		b := opexp2.Baseline{Manager: agent.ID == source.ManagerID, Summaries: e.summaries[agent.ID], Now: now}
		b.MaxHours, b.HoursProblem = whole(policy, agent.ID, "op.exp.2", "P-09", "param.not_hours")
		if c, ok := e.wazuh[agent.ID]; ok {
			b.Config = &c
		}
		if r, ok := e.reporting[agent.ID]; ok {
			b.Reporting = &r
		}
		policies, err := policy.List(agent.ID, "op.exp.2", "P-01")
		b.Policies, b.PolicyProblem = policies, problemOf("P-01", err)

		minScore, err := policy.Number(agent.ID, "op.exp.2", "P-05")
		problem := problemOf("op.exp.2 P-05", err)
		if problem.IsZero() {
			problem = daysProblem
		}
		var lowest map[string]map[string]int
		if problem.IsZero() {
			if lowest, err = e.lowestFor(ctx, days); err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
			}
		}
		return JudgeEV01(opexp2.JudgeEV01(b), policies, lowest[agent.ID], int(minScore), days, problem)
	})

	paths, pathsErr := policy.List(agent.ID, control, "P-04")
	var watches *fact.AuditWatchSnapshot
	if w, ok := e.watches[agent.ID]; ok {
		watches = &w
	}
	var wazuh *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		wazuh = &c
	}
	chain := opacc4.AuditChain(watches, wazuh, false, paths)
	edits := Edits(accesses, paths)

	judge("EV-02", []string{"audit", "accounts"}, func() verdict.Judgement {
		if pathsErr != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", pathsErr))
		}
		authorised, err := policy.List(agent.ID, control, "P-03")
		return JudgeEV02(edits, accounts, authorised, problemOf("P-03", err), chain)
	})

	fim, err := e.facts.FIMChanges(ctx, agent.ID, window)
	read("fim", err)

	judge("EV-05", []string{"fim"}, func() verdict.Judgement {
		if pathsErr != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", pathsErr))
		}
		rows, err := policy.List(agent.ID, opexp5.Control, opexp5.RegisterParam)
		return JudgeEV05(fim, paths, opexp5.ParseRegister(rows), agent.Name, problemOf("op.exp.5 P-10", err), window)
	})

	// The reaction to notified vulnerabilities is op.exp.4's remediation within deadline.
	judge("EV-06", nil, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, "op.exp.4", "P-01")
		deadlines, problem := opexp4.Deadlines(rows)
		if err != nil {
			problem = passes.Param("op.exp.4 P-01", err)
		}
		return opexp4.JudgeEV02(agent.ID == source.ManagerID, e.vulns[agent.ID], deadlines, problem, now)
	})

	// The reaction to incidents is the improvement measures recorded in op.exp.7's register.
	judge("EV-07", nil, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, opexp7.Control, opexp7.RegisterParam)
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("op.exp.7 P-13", err))
		}
		return opexp7.JudgeEV12(opexp7.Of(opexp7.ParseRegister(rows), agent.Name, now))
	})

	judge("EV-08", []string{"audit", "accounts"}, func() verdict.Judgement {
		if pathsErr != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", pathsErr))
		}
		max, err := policy.Number(agent.ID, control, "P-09")
		problem := problemOf("P-09", err)
		if err == nil && (max < 1 || max != float64(int(max))) {
			problem = catalog.Says("param.not_whole", "param", "P-09", "value", max)
		}
		return JudgeEV08(edits, accounts, int(max), problem, chain)
	})

	judge("EV-03", nil, func() verdict.Judgement {
		var selection *fact.PackageSelection
		if s, ok := e.selections[agent.ID]; ok {
			selection = &s
		}
		authorised, err := policy.List(agent.ID, control, "P-01")
		problem := catalog.Message{}
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			problem = passes.Param("P-01", err)
		}
		return JudgeEV03(e.installed[agent.ID], selection, authorised, problem)
	})

	judge("EV-04", []string{"listening"}, func() verdict.Judgement {
		var units *fact.UnitSnapshot
		if u, ok := e.units[agent.ID]; ok {
			units = &u
		}
		authorised, err := policy.List(agent.ID, control, "P-02")
		return JudgeEV04(units, listening, sockets, authorised, problemOf("P-02", err))
	})

	judge("EV-09", nil, func() verdict.Judgement {
		var b *fact.BackupSnapshot
		if s, ok := e.backups[agent.ID]; ok {
			b = &s
		}
		_, err := policy.List(agent.ID, control, "P-07")
		problem := problemOf("P-07", err)
		hours, hoursProblem := whole(policy, agent.ID, control, "P-10", "param.not_hours")
		if problem.IsZero() {
			problem = hoursProblem
		}
		return JudgeEV09(b, groupconf.BackupSources(policy, agent.ID), hours, problem, now)
	})

	judge("EV-10", nil, func() verdict.Judgement {
		if !daysProblem.IsZero() {
			return passes.Gap(verdict.CauseConfiguration, daysProblem)
		}
		return JudgeEV10(e.regressions[agent.ID], now.Add(-time.Duration(days)*24*time.Hour), days)
	})

	judge("EV-11", nil, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, control, "P-11")
		maxDays, daysProblem := whole(policy, agent.ID, control, "P-05", "param.not_days")
		j, _ := passes.Review(rows, problemOf("P-11", err), "P-11", maxDays, daysProblem, "P-05", now)
		return j
	})

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

package opexp8

import (
	"context"
	"errors"
	"fmt"
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
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	MalwareProtections(ctx context.Context, since time.Time) (map[string]fact.MalwareProtection, error)
	TimeSyncs(ctx context.Context, since time.Time) (map[string]fact.TimeSync, error)
	Reporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	MonitoringHistory(ctx context.Context, agentID string, since time.Time) ([]source.MonitoringRecord, error)
	AuditFields(ctx context.Context, agentID string, since time.Time) (int, map[string]int, error)
	Retention(ctx context.Context) (int, bool, error)
	NewestSnapshot(ctx context.Context) (time.Time, error)
	ACLSnapshots(ctx context.Context, since time.Time) (map[string]fact.ACLSnapshot, error)
	ACLRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ACLRecord, error)
	ActiveResponseTimes(ctx context.Context, since time.Time) (map[string][]time.Time, error)
}

const control = "op.exp.8"

type Evaluator struct {
	facts Facts

	pass         evaluator.Pass
	watches      map[string]fact.AuditWatchSnapshot
	wazuh        map[string]fact.WazuhAgentConfig
	protection   map[string]fact.MalwareProtection
	clocks       map[string]fact.TimeSync
	reporting    map[string]source.Reporting
	acls         map[string]fact.ACLSnapshot
	responses    map[string][]time.Time
	retention    int
	managed      bool
	retentionErr error
	snapshot     time.Time
	snapshotErr  error
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
		{"audit watches", func() (err error) { e.watches, err = e.facts.AuditWatchSnapshots(ctx, w); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"protection", func() (err error) { e.protection, err = e.facts.MalwareProtections(ctx, w); return }},
		{"time", func() (err error) { e.clocks, err = e.facts.TimeSyncs(ctx, w); return }},
		{"monitoring", func() (err error) { e.reporting, err = e.facts.Reporting(ctx, pass.LookbackStart); return }},
		{"acl", func() (err error) { e.acls, err = e.facts.ACLSnapshots(ctx, w); return }},
		{"active responses", func() (err error) { e.responses, err = e.facts.ActiveResponseTimes(ctx, w); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	// The indexer's own settings: a user without the right to read them leaves those evidences unproven,
	// not the whole control.
	e.retention, e.managed, e.retentionErr = e.facts.Retention(ctx)
	e.snapshot, e.snapshotErr = e.facts.NewestSnapshot(ctx)
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, window := e.pass.Now, e.pass.WindowStart
	manager := agent.ID == source.ManagerID
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }

	var watches *fact.AuditWatchSnapshot
	if x, ok := e.watches[agent.ID]; ok {
		watches = &x
	}
	var c, managerConfig *fact.WazuhAgentConfig
	if x, ok := e.wazuh[agent.ID]; ok {
		c = &x
	}
	if x, ok := e.wazuh[source.ManagerID]; ok {
		managerConfig = &x
	}

	put("EV-01", JudgeEV01(watches, c))

	hours, hoursProblem := whole(policy, agent.ID, "P-12", "param.not_hours")
	var reporting *source.Reporting
	if r, ok := e.reporting[agent.ID]; ok {
		reporting = &r
	}
	coverage := opexp1.JudgeEV04(reporting, manager, hours, hoursProblem, now)
	put("EV-02", coverage)

	total, fields, err := e.facts.AuditFields(ctx, agent.ID, window)
	if err != nil {
		return results, fmt.Errorf("audit fields: %w", err)
	}
	put("EV-03", JudgeEV03(total, fields))

	var history []source.MonitoringRecord
	if !manager {
		if history, err = e.facts.MonitoringHistory(ctx, agent.ID, window); err != nil {
			return results, fmt.Errorf("monitoring history: %w", err)
		}
	}
	put("EV-04", JudgeEV04(history, manager, hours, hoursProblem, window, now))

	put("EV-05", func() verdict.Judgement {
		rows, err := policy.List(agent.ID, control, "P-13")
		days, daysProblem := whole(policy, agent.ID, "P-04", "param.not_days")
		j, _ := passes.Review(rows, problemOf("P-13", err), "P-13", days, daysProblem, "P-04", now)
		return j
	}())

	put("EV-06", func() verdict.Judgement {
		var t *fact.TimeSync
		if x, ok := e.clocks[agent.ID]; ok {
			t = &x
		}
		sources, err := policy.List(agent.ID, control, "P-05")
		if errors.Is(err, params.ErrNotSet) {
			err = nil
		}
		offset, offsetErr := policy.Number(agent.ID, control, "P-06")
		problem := problemOf("P-05", err)
		if problem.IsZero() {
			problem = problemOf("P-06", offsetErr)
		}
		return JudgeEV06(t, sources, offset, problem)
	}())

	put("EV-07", func() verdict.Judgement {
		if e.retentionErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opexp8.indexer_unread", "error", e.retentionErr.Error()))
		}
		rows, err := policy.List(agent.ID, control, "P-07")
		return JudgeEV07(e.retention, e.managed, LongestRetention(rows), problemOf("P-07", err))
	}())

	put("EV-08", func() verdict.Judgement {
		paths, err := policy.List(agent.ID, control, "P-14")
		problem := problemOf("P-14", err)
		accounts, accErr := policy.ListColumn(agent.ID, control, "P-08", 0)
		if problem.IsZero() {
			problem = problemOf("P-08", accErr)
		}
		var s *fact.ACLSnapshot
		var records []fact.ACLRecord
		if x, ok := e.acls[agent.ID]; ok {
			s = &x
			if records, err = e.facts.ACLRecords(ctx, agent.ID, x.RecordsRun(), e.pass.LookbackStart); err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
			}
		}
		return JudgeEV08(s, records, paths, accounts, problem)
	}())

	put("EV-09", func() verdict.Judgement {
		if e.snapshotErr != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opexp8.indexer_unread", "error", e.snapshotErr.Error()))
		}
		rows, err := policy.List(agent.ID, control, "P-09")
		return JudgeEV09(e.snapshot, ShortestFrequency(rows), problemOf("P-09", err), now)
	}())

	sets, err := policy.ListColumn(agent.ID, control, "P-10", 0)
	put("EV-10", JudgeEV10(managerConfig, sets, problemOf("P-10", err)))

	actions, err := policy.ListColumn(agent.ID, control, "P-11", 0)
	var p *fact.MalwareProtection
	if x, ok := e.protection[agent.ID]; ok {
		p = &x
	}
	put("EV-11", JudgeEV11(actions, c, p, problemOf("P-11", err)))
	put("EV-12", JudgeEV12(e.responses[agent.ID], window))
	put("EV-13", JudgeEV13(coverage, c))

	return results, nil
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

func problemOf(id string, err error) catalog.Message {
	if err != nil {
		return passes.Param(id, err)
	}
	return catalog.Message{}
}

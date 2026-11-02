package opexp2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	FleetReporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	SCASummaries(ctx context.Context, since time.Time) (map[string][]source.SCASummary, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error)
	ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	ACLSnapshots(ctx context.Context, since time.Time) (map[string]fact.ACLSnapshot, error)
	ACLRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ACLRecord, error)
	Virtualizations(ctx context.Context, since time.Time) (map[string]fact.Virtualization, error)
}

const control = "op.exp.2"

// SCA summaries are read back this far: Wazuh only raises one when the result changes.
const summariesHorizon = 366 * 24 * time.Hour

type Evaluator struct {
	facts Facts

	pass           evaluator.Pass
	wazuh          map[string]fact.WazuhAgentConfig
	reporting      map[string]source.Reporting
	summaries      map[string][]source.SCASummary
	identities     map[string][]fact.IdentitySnapshot
	listening      map[string]fact.ListeningSnapshot
	configs        map[string]fact.ConfigSnapshot
	acls           map[string]fact.ACLSnapshot
	virtualization map[string]fact.Virtualization
	reportingNames map[string]bool
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
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"monitoring", func() (err error) { e.reporting, err = e.facts.FleetReporting(ctx, pass.LookbackStart); return }},
		{"sca", func() (err error) {
			e.summaries, err = e.facts.SCASummaries(ctx, pass.Now.Add(-summariesHorizon))
			return
		}},
		{"identity", func() (err error) { e.identities, err = e.facts.IdentitySnapshots(ctx, w, 1); return }},
		{"listening", func() (err error) { e.listening, err = e.facts.ListeningSnapshots(ctx, w); return }},
		{"config", func() (err error) { e.configs, err = e.facts.ConfigSnapshots(ctx, w); return }},
		{"acl", func() (err error) { e.acls, err = e.facts.ACLSnapshots(ctx, w); return }},
		{"virtualization", func() (err error) { e.virtualization, err = e.facts.Virtualizations(ctx, w); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	// A host of P-06 is named as its agent is: whether each agent reports, by name.
	e.reportingNames = map[string]bool{}
	for id, r := range e.reporting {
		if r.Name != "" {
			e.reportingNames[r.Name] = id == source.ManagerID || r.Status == "active"
		}
	}

	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart
	today := now.UTC().Truncate(24 * time.Hour)

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

	accounts := Accounts{}
	if list, ok := e.identities[agent.ID]; ok && len(list) > 0 {
		records, err := e.facts.IdentityRecords(ctx, agent.ID, list[0].RecordsRun(), since)
		read("accounts", err)
		accounts = Accounts{Snapshot: &list[0], Records: records}
	}

	listening := Listening{}
	if s, ok := e.listening[agent.ID]; ok {
		sockets, err := e.facts.ListeningSockets(ctx, agent.ID, s.RecordsRun(), since)
		read("listening", err)
		listening = Listening{Snapshot: &s, Sockets: sockets}
	}

	defaults := Defaults{Accounts: accounts}
	if s, ok := e.configs[agent.ID]; ok {
		files, err := e.facts.ConfigFiles(ctx, agent.ID, s.RecordsRun(), since)
		read("config", err)
		defaults.Settings = opacc6.Settings{Snapshot: &s, Files: files}
	}
	if s, ok := e.acls[agent.ID]; ok {
		records, err := e.facts.ACLRecords(ctx, agent.ID, s.RecordsRun(), since)
		read("acl", err)
		defaults.ACL, defaults.Files = &s, records
	}

	logins, err := e.facts.Logins(ctx, agent.ID, window)
	read("logins", err)

	baseline := Baseline{Manager: agent.ID == source.ManagerID, Summaries: e.summaries[agent.ID], Now: now}
	baseline.MaxHours, baseline.HoursProblem = whole(policy, agent.ID, "P-09", "param.not_hours")
	if c, ok := e.wazuh[agent.ID]; ok {
		baseline.Config = &c
	}
	if r, ok := e.reporting[agent.ID]; ok {
		baseline.Reporting = &r
	}
	policies, err := policy.List(agent.ID, control, "P-01")
	baseline.Policies, baseline.PolicyProblem = policies, problemOf("P-01", err)

	judge("EV-01", nil, func() verdict.Judgement { return JudgeEV01(baseline) })

	judge("EV-06", nil, func() verdict.Judgement {
		v, err := policy.Number(agent.ID, control, "P-05")
		problem := problemOf("P-05", err)
		if err == nil && (v < 0 || v > 100) {
			problem = catalog.Says("opexp2.not_percent", "param", "P-05", "value", v)
		}
		return JudgeEV06(baseline, int(v), problem)
	})

	judge("EV-02", []string{"accounts", "logins"}, func() verdict.Judgement {
		standard, err := policy.List(agent.ID, control, "P-03")
		return JudgeEV02(accounts, standard, problemOf("P-03", err), logins, today)
	})

	judge("EV-03", []string{"listening"}, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, control, "P-02")
		return JudgeEV03(listening, rows, problemOf("P-02", err))
	})

	judge("EV-04", []string{"accounts", "config", "acl"}, func() verdict.Judgement {
		files, err := policy.List(agent.ID, control, "P-08")
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-08", err))
		}
		rows, err := policy.List(agent.ID, control, "P-04")
		if err != nil && !errors.Is(err, params.ErrNotSet) {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-04", err))
		}
		return JudgeEV04(defaults, agent.Name, files, ParseExceptions(rows), today)
	})

	judge("EV-05", nil, func() verdict.Judgement {
		var v *fact.Virtualization
		if x, ok := e.virtualization[agent.ID]; ok {
			v = &x
		}
		rows, err := policy.List(agent.ID, control, "P-06")
		return JudgeEV05(v, agent.Name, rows, problemOf("P-06", err), e.reportingNames)
	})

	return results, errors.Join(errs...)
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

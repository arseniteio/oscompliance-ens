package opacc4

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc6"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is what op.acc.4 reads (source.Source in production).
type Facts interface {
	FirewallSnapshots(ctx context.Context, since time.Time) (map[string]fact.FirewallSnapshot, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	SudoersSnapshots(ctx context.Context, since time.Time) (map[string]fact.SudoersSnapshot, error)
	SudoGrants(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SudoGrant, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error)
	GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]source.AuditAccess, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	AuthLogProbes(ctx context.Context, since time.Time, n int) (map[string][]fact.AuthLogProbe, error)
	ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error)
}

const control = "op.acc.4"

// Evaluator judges op.acc.4.
type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	firewalls  map[string]fact.FirewallSnapshot
	configs    map[string]fact.ConfigSnapshot
	sudoers    map[string]fact.SudoersSnapshot
	identities map[string][]fact.IdentitySnapshot
	groups     map[string]fact.GroupSnapshot
	watches    map[string]fact.AuditWatchSnapshot
	wazuh      map[string]fact.WazuhAgentConfig
	probes     map[string][]fact.AuthLogProbe
	seen       map[string]map[string]bool
}

// NewEvaluator returns the op.acc.4 evaluator.
func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

// Control is the catalog id.
func (e *Evaluator) Control() string { return control }

// Begin reads the newest snapshot of every fact type, for every agent.
func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	w := pass.WindowStart
	var err error

	steps := []struct {
		name string
		do   func() error
	}{
		{"firewall", func() (err error) { e.firewalls, err = e.facts.FirewallSnapshots(ctx, w); return }},
		{"config", func() (err error) { e.configs, err = e.facts.ConfigSnapshots(ctx, w); return }},
		{"sudoers", func() (err error) { e.sudoers, err = e.facts.SudoersSnapshots(ctx, w); return }},
		{"identity", func() (err error) { e.identities, err = e.facts.IdentitySnapshots(ctx, w, 1); return }},
		{"groups", func() (err error) { e.groups, err = e.facts.GroupSnapshots(ctx, w); return }},
		{"audit watches", func() (err error) { e.watches, err = e.facts.AuditWatchSnapshots(ctx, w); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"probes", func() (err error) { e.probes, err = e.facts.AuthLogProbes(ctx, w, 48); return }},
		{"probe alerts", func() (err error) { e.seen, err = e.facts.ProbesSeen(ctx, w); return }},
	}

	for _, s := range steps {
		if err = s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}

	return nil
}

// Agent judges the eight evidences of op.acc.4. A read that fails leaves
// out the evidences that need it.
func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

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

	since, window := e.pass.LookbackStart, e.pass.WindowStart

	// Facts.
	settings := opacc6.Settings{}
	if s, ok := e.configs[agent.ID]; ok {
		files, err := e.facts.ConfigFiles(ctx, agent.ID, s.RunID, since)
		read("config", err)
		settings = opacc6.Settings{Snapshot: &s, Files: files}
	}

	sudoers := Sudoers{}
	if s, ok := e.sudoers[agent.ID]; ok {
		grants, err := e.facts.SudoGrants(ctx, agent.ID, s.RunID, since)
		read("sudoers", err)
		sudoers = Sudoers{Snapshot: &s, Grants: grants}
	}

	accounts := Accounts{}
	if list, ok := e.identities[agent.ID]; ok && len(list) > 0 {
		records, err := e.facts.IdentityRecords(ctx, agent.ID, list[0].RunID, since)
		read("accounts", err)
		accounts.Identity, accounts.IdentityRecords = &list[0], records
	}
	if g, ok := e.groups[agent.ID]; ok {
		records, err := e.facts.GroupRecords(ctx, agent.ID, g.RunID, since)
		read("accounts", err)
		accounts.Groups, accounts.GroupRecords = &g, records
	}

	accesses, err := e.facts.AuditAccesses(ctx, agent.ID, window)
	read("audit", err)
	logins, err := e.facts.Logins(ctx, agent.ID, window)
	read("logins", err)

	var firewall *fact.FirewallSnapshot
	if f, ok := e.firewalls[agent.ID]; ok {
		firewall = &f
	}
	var watches *fact.AuditWatchSnapshot
	if w, ok := e.watches[agent.ID]; ok {
		watches = &w
	}
	var wazuh *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		wazuh = &c
	}

	// Parameters.
	matrixRows, err := policy.List(agent.ID, control, "P-01")
	matrixProblem := problemOf(err)
	matrix := ParseMatrix(matrixRows)

	// EV-01: deny by default.
	judge("EV-01", []string{"config"}, func() verdict.Judgement {
		in := EV01Input{Firewall: firewall, Settings: settings, ResourcesProblem: matrixProblem}
		for _, r := range matrix {
			in.Resources = append(in.Resources, r.Resource)
		}
		return JudgeEV01(in)
	})

	// EV-02: sudo grants against the matrix.
	judge("EV-02", []string{"sudoers"}, func() verdict.Judgement { return JudgeEV02(sudoers, matrix, matrixProblem) })

	// EV-03: members of the privileged groups.
	judge("EV-03", []string{"accounts"}, func() verdict.Judgement {
		groups, err := policy.List(agent.ID, control, "P-06")
		problem := ""
		switch {
		case err != nil:
			problem = "P-06: " + err.Error()
		case matrixProblem != "":
			problem = "P-01: " + matrixProblem
		}
		return JudgeEV03(accounts, groups, matrix, problem)
	})

	// EV-04: who changes rights.
	judge("EV-04", []string{"audit", "accounts"}, func() verdict.Judgement {
		competent, err := policy.ListColumn(agent.ID, control, "P-02", 0)
		return JudgeEV04(accesses, accounts, competent, problemOf(err), AuditChain(watches, wazuh, true, nil))
	})

	// EV-05: periodic review.
	judge("EV-05", nil, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, control, ReviewParam)
		days, daysErr := policy.Number(agent.ID, control, "P-03")
		daysProblem := problemOf(daysErr)
		if daysErr == nil && (days < 1 || days != float64(int(days))) {
			daysProblem = fmt.Sprintf("%v is not a whole number of days", days)
		}
		return JudgeEV05(rows, problemOf(err), int(days), daysProblem, e.pass.Now)
	})

	// EV-06: remote access.
	judge("EV-06", []string{"logins"}, func() verdict.Judgement {
		authorised, err := policy.List(agent.ID, control, "P-05")
		return JudgeEV06(logins, authorised, problemOf(err), passes.ProbeResult(e.probes[agent.ID], e.seen[agent.ID], e.pass.Now))
	})

	// EV-07: need to know.
	judge("EV-07", []string{"audit", "accounts"}, func() verdict.Judgement {
		rows, err := policy.List(agent.ID, control, "P-07")
		resources := ParseSensitive(rows)
		var paths []string
		for _, r := range resources {
			paths = append(paths, r.Path)
		}
		return JudgeEV07(accesses, accounts, resources, problemOf(err), AuditChain(watches, wazuh, false, paths))
	})

	// EV-08: privileges above the minimum.
	judge("EV-08", []string{"sudoers", "accounts", "config"}, func() verdict.Judgement {
		in := EV08Input{Sudoers: sudoers, Accounts: accounts, UIDMin: 1000, Rows: matrix, Problem: matrixProblem}
		if v, _, _ := settings.Lookup("/etc/login.defs", "", "UID_MIN"); v.Found {
			if n, err := strconv.Atoi(v.Value); err == nil {
				in.UIDMin = n
			}
		}
		return JudgeEV08(in)
	})

	return results, errors.Join(errs...)
}

func problemOf(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

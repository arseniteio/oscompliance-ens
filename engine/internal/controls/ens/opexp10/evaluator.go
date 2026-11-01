package opexp10

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Facts interface {
	KeySnapshots(ctx context.Context, since time.Time) (map[string]fact.KeySnapshot, error)
	KeyRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.KeyRecord, error)
	CertificateRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.CertificateRecord, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]source.AuditAccess, error)
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error)
	ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
}

const control = "op.exp.10"

type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	keys       map[string]fact.KeySnapshot
	watches    map[string]fact.AuditWatchSnapshot
	wazuh      map[string]fact.WazuhAgentConfig
	identities map[string][]fact.IdentitySnapshot
	configs    map[string]fact.ConfigSnapshot
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
		{"keys", func() (err error) { e.keys, err = e.facts.KeySnapshots(ctx, w); return }},
		{"audit watches", func() (err error) { e.watches, err = e.facts.AuditWatchSnapshots(ctx, w); return }},
		{"wazuh config", func() (err error) { e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, w); return }},
		{"identity", func() (err error) { e.identities, err = e.facts.IdentitySnapshots(ctx, w, 1); return }},
		{"config", func() (err error) { e.configs, err = e.facts.ConfigSnapshots(ctx, w); return }},
	}
	for _, s := range steps {
		if err := s.do(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now, since, window := e.pass.Now, e.pass.LookbackStart, e.pass.WindowStart
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	var errs []error
	read := func(name string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}

	keys := Keys{}
	if s, ok := e.keys[agent.ID]; ok {
		keys.Snapshot = &s
		var err error
		keys.Keys, err = e.facts.KeyRecords(ctx, agent.ID, s.RecordsRun(), since)
		read("keys", err)
		keys.Certificates, err = e.facts.CertificateRecords(ctx, agent.ID, s.RecordsRun(), since)
		read("certificates", err)
	}
	accounts := opacc4.Accounts{}
	if list, ok := e.identities[agent.ID]; ok && len(list) > 0 {
		records, err := e.facts.IdentityRecords(ctx, agent.ID, list[0].RecordsRun(), since)
		read("accounts", err)
		accounts.Identity, accounts.IdentityRecords = &list[0], records
	}
	accesses, err := e.facts.AuditAccesses(ctx, agent.ID, window)
	read("audit", err)
	settings := opacc6.Settings{}
	if s, ok := e.configs[agent.ID]; ok {
		files, err := e.facts.ConfigFiles(ctx, agent.ID, s.RecordsRun(), since)
		read("config", err)
		settings = opacc6.Settings{Snapshot: &s, Files: files}
	}
	logins, err := e.facts.Logins(ctx, agent.ID, window)
	read("logins", err)
	if len(errs) > 0 {
		return results, errors.Join(errs...)
	}

	storeRows, err := policy.List(agent.ID, control, "P-02")
	stores, storesProblem := ParseStores(storeRows), problemOf("P-02", err)
	var paths []string
	for _, s := range stores {
		paths = append(paths, s.Path)
	}
	var watches *fact.AuditWatchSnapshot
	if w, ok := e.watches[agent.ID]; ok {
		watches = &w
	}
	var wazuh *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		wazuh = &c
	}

	allowed, err := policy.ListColumn(agent.ID, control, "P-08", 0)
	problem := storesProblem
	if problem.IsZero() {
		problem = problemOf("P-08", err)
	}
	put("EV-01", JudgeEV01(accesses, accounts, stores, allowed, problem, opacc4.AuditChain(watches, wazuh, false, paths)))
	put("EV-02", JudgeEV02(keys, stores, storesProblem))

	algorithms, err := policy.List(agent.ID, control, "P-03")
	algorithmsProblem := problemOf("P-03", err)
	put("EV-03", JudgeEV03(settings, Algorithms(algorithms), algorithmsProblem))
	put("EV-04", JudgeEV04(logins, Algorithms(algorithms), algorithmsProblem))

	media, err := policy.List(agent.ID, control, "P-05")
	if errors.Is(err, params.ErrNotSet) {
		err = nil
	}
	put("EV-05", func() verdict.Judgement {
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, passes.Param("P-05", err))
		}
		return JudgeEV05(Operation(media, agent.Name), accesses, accounts, opacc4.AuditChain(watches, wazuh, false, nil))
	}())

	inventory, err := policy.List(agent.ID, control, "P-01")
	put("EV-06", JudgeEV06(keys, inventory, agent.Name, problemOf("P-01", err)))

	notice, err := policy.Number(agent.ID, control, "P-10")
	put("EV-07", JudgeEV07(keys, int(notice), problemOf("P-10", err), now))
	put("EV-08", JudgeEV08(keys, stores, storesProblem))

	return results, nil
}

func problemOf(id string, err error) catalog.Message {
	if err != nil {
		return passes.Param(id, err)
	}
	return catalog.Message{}
}

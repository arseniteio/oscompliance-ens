package opacc2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is what op.acc.2 reads (source.Source in production).
type Facts interface {
	IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error)
	IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error)
	GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error)
	GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error)
	SweepSnapshots(ctx context.Context, since time.Time) (map[string]fact.FileSweepSnapshot, error)
	SpecialFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SpecialFile, error)
	UmaskSnapshots(ctx context.Context, since time.Time) (map[string]fact.UmaskSnapshot, error)
	SudoersSnapshots(ctx context.Context, since time.Time) (map[string]fact.SudoersSnapshot, error)
	SudoGrants(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SudoGrant, error)
	WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error)
	ACLSnapshots(ctx context.Context, since time.Time) (map[string]fact.ACLSnapshot, error)
	ACLRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ACLRecord, error)
	AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error)
	FIMChanges(ctx context.Context, agentID string, since time.Time) ([]source.FIMChange, error)
	Elevations(ctx context.Context, agentID string, since time.Time) ([]source.Elevation, error)
	Logins(ctx context.Context, agentID string, since time.Time) ([]source.Login, error)
	AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]source.AuditAccess, error)
	AuthLogProbes(ctx context.Context, since time.Time, n int) (map[string][]fact.AuthLogProbe, error)
	ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error)
}

// maxProbes is how many probes of the window are compared.
const maxProbes = 48

const control = "op.acc.2"

// Evaluator judges op.acc.2.
type Evaluator struct {
	facts Facts

	pass       evaluator.Pass
	identities map[string][]fact.IdentitySnapshot
	groups     map[string]fact.GroupSnapshot
	sweeps     map[string]fact.FileSweepSnapshot
	umasks     map[string]fact.UmaskSnapshot
	sudoers    map[string]fact.SudoersSnapshot
	wazuh      map[string]fact.WazuhAgentConfig
	acls       map[string]fact.ACLSnapshot
	watches    map[string]fact.AuditWatchSnapshot
	probes     map[string][]fact.AuthLogProbe
	seen       map[string]map[string]bool
}

// NewEvaluator returns the op.acc.2 evaluator.
func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

// Control is the catalog id.
func (e *Evaluator) Control() string { return control }

// Begin reads the newest snapshot of every fact type, for every agent.
func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	var err error

	if e.identities, err = e.facts.IdentitySnapshots(ctx, pass.WindowStart, 1); err != nil {
		return fmt.Errorf("identity snapshots: %w", err)
	}
	if e.groups, err = e.facts.GroupSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("group snapshots: %w", err)
	}
	if e.sweeps, err = e.facts.SweepSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("sweep snapshots: %w", err)
	}
	if e.umasks, err = e.facts.UmaskSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("umask snapshots: %w", err)
	}
	if e.sudoers, err = e.facts.SudoersSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("sudoers snapshots: %w", err)
	}
	if e.wazuh, err = e.facts.WazuhAgentConfigs(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("wazuh agent configs: %w", err)
	}
	if e.acls, err = e.facts.ACLSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("acl snapshots: %w", err)
	}
	if e.watches, err = e.facts.AuditWatchSnapshots(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("audit watch snapshots: %w", err)
	}
	if e.probes, err = e.facts.AuthLogProbes(ctx, pass.WindowStart, maxProbes); err != nil {
		return fmt.Errorf("auth log probes: %w", err)
	}
	if e.seen, err = e.facts.ProbesSeen(ctx, pass.WindowStart); err != nil {
		return fmt.Errorf("probe alerts: %w", err)
	}

	return nil
}

// Agent judges the seven evidences of op.acc.2. A read that fails leaves
// out the evidences that need it: they count as COLLECTION gaps.
func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	results := map[string]evaluator.Result{}
	var errs []error
	since := e.pass.LookbackStart

	// The sweep feeds EV-01 and EV-07.
	var sw Sweep
	if s, ok := e.sweeps[agent.ID]; ok {
		files, err := e.facts.SpecialFiles(ctx, agent.ID, s.RunID, since)
		if err != nil {
			errs = append(errs, fmt.Errorf("special files: %w", err))
		} else {
			sw = Sweep{Snapshot: &s, Files: files}
		}
	}
	sweepRead := len(errs) == 0

	if sweepRead {
		ev01 := EV01Input{Sweep: sw}
		if u, ok := e.umasks[agent.ID]; ok {
			ev01.Umask = &u
		}
		ev01.Scope, ev01.Exceptions, ev01.StickyAllowed, ev01.MinUmask, ev01.ConfigProblem = ev01Params(policy, agent.ID)
		results["EV-01"] = evaluator.Result{Judgement: JudgeEV01(ev01), RunID: runOf(sw.Snapshot)}

		ev07 := EV07Input{Sweep: sw}
		authorized, err := policy.List(agent.ID, control, "P-10")
		if err != nil {
			ev07.AuthorizedProblem = "P-10: " + err.Error()
		}
		ev07.Authorized = authorized
		results["EV-07"] = evaluator.Result{Judgement: JudgeEV07(ev07), RunID: runOf(sw.Snapshot)}
	}

	// EV-05: accounts, groups and sudoers.
	ev05 := EV05Input{}
	var readErr error

	if list, ok := e.identities[agent.ID]; ok && len(list) > 0 {
		ev05.Accounts.Identity = &list[0]
		ev05.Accounts.IdentityRecords, readErr = e.facts.IdentityRecords(ctx, agent.ID, list[0].RunID, since)
	}
	if g, ok := e.groups[agent.ID]; ok && readErr == nil {
		ev05.Accounts.Groups = &g
		ev05.Accounts.GroupRecords, readErr = e.facts.GroupRecords(ctx, agent.ID, g.RunID, since)
	}
	if s, ok := e.sudoers[agent.ID]; ok && readErr == nil {
		ev05.Sudoers.Snapshot = &s
		ev05.Sudoers.Grants, readErr = e.facts.SudoGrants(ctx, agent.ID, s.RunID, since)
	}

	if readErr != nil {
		errs = append(errs, fmt.Errorf("EV-05 facts: %w", readErr))
	} else {
		ev05.Groups, ev05.Declared, ev05.ConfigProblem = ev05Params(policy, agent.ID)
		runID := ""
		if ev05.Sudoers.Snapshot != nil {
			runID = ev05.Sudoers.Snapshot.RunID
		}
		results["EV-05"] = evaluator.Result{Judgement: JudgeEV05(ev05), RunID: runID}
	}

	window := e.pass.WindowStart
	var config *fact.WazuhAgentConfig
	if c, ok := e.wazuh[agent.ID]; ok {
		config = &c
	}

	// EV-02: Wazuh FIM on the P-02 paths.
	if changes, err := e.facts.FIMChanges(ctx, agent.ID, window); err != nil {
		errs = append(errs, fmt.Errorf("fim changes: %w", err))
	} else {
		in := EV02Input{Config: config, Changes: changes, Window: e.pass.Now.Sub(window)}
		if in.Critical, err = policy.List(agent.ID, control, "P-02"); err != nil {
			in.CriticalProblem = err.Error()
		}
		results["EV-02"] = evaluator.Result{Judgement: JudgeEV02(in)}
	}

	// EV-03: sudo and su, against the privileged accounts of EV-05.
	elevations, err := e.facts.Elevations(ctx, agent.ID, window)
	if err == nil {
		var logins []source.Login
		if logins, err = e.facts.Logins(ctx, agent.ID, window); err == nil {
			for _, l := range logins {
				if l.Method == source.MethodSU {
					elevations = append(elevations, source.Elevation{Time: l.Time, From: l.SourceUser, To: l.Account, Method: "su"})
				}
			}
		}
	}
	if err != nil || readErr != nil {
		errs = append(errs, fmt.Errorf("EV-03 facts: %w", errors.Join(err, readErr)))
	} else {
		in := EV03Input{Accounts: ev05.Accounts, Sudoers: ev05.Sudoers, Elevations: elevations,
			Log: passes.ProbeResult(e.probes[agent.ID], e.seen[agent.ID], e.pass.Now)}
		in.Groups, _ = policy.List(agent.ID, control, "P-12")
		results["EV-03"] = evaluator.Result{Judgement: JudgeEV03(in)}
	}

	// EV-04: rights of the P-08 paths.
	acls := ACLs{}
	var aclErr error
	if s, ok := e.acls[agent.ID]; ok {
		acls.Snapshot = &s
		acls.Records, aclErr = e.facts.ACLRecords(ctx, agent.ID, s.RunID, since)
	}
	if aclErr != nil {
		errs = append(errs, fmt.Errorf("acl records: %w", aclErr))
	} else {
		var err error
		in := EV04Input{ACLs: acls}
		if in.Rows, err = policy.List(agent.ID, control, "P-08"); err != nil {
			in.RowsProblem = err.Error()
		}
		runID := ""
		if acls.Snapshot != nil {
			runID = acls.Snapshot.RunID
		}
		results["EV-04"] = evaluator.Result{Judgement: JudgeEV04(in), RunID: runID}
	}

	// EV-06: audited accesses against P-06 and P-09.
	if accesses, err := e.facts.AuditAccesses(ctx, agent.ID, window); err != nil {
		errs = append(errs, fmt.Errorf("audit accesses: %w", err))
	} else {
		in := EV06Input{Config: config, Accesses: accesses, Accounts: ev05.Accounts}
		if w, ok := e.watches[agent.ID]; ok {
			in.Watches = &w
		}
		var problems []string
		if in.Rules, err = policy.List(agent.ID, control, "P-06"); err != nil {
			problems = append(problems, "P-06: "+err.Error())
		}
		if in.Profiles, err = policy.List(agent.ID, control, "P-09"); err != nil {
			problems = append(problems, "P-09: "+err.Error())
		}
		in.Problem = joinProblems(problems)
		results["EV-06"] = evaluator.Result{Judgement: JudgeEV06(in)}
	}

	return results, errors.Join(errs...)
}

func runOf(s *fact.FileSweepSnapshot) string {
	if s == nil {
		return ""
	}
	return s.RunID
}

// ev01Params reads P-02, P-11, P-03 and P-07. Every missing required one is
// named; P-11 is optional.
func ev01Params(policy params.Lister, agentID string) (scope, exceptions []string, sticky bool, umask, problem string) {

	var problems []string

	scope, err := policy.List(agentID, control, "P-02")
	if err != nil {
		problems = append(problems, "P-02: "+err.Error())
	}

	exceptions, err = policy.List(agentID, control, "P-11")
	if err != nil && !errors.Is(err, params.ErrNotSet) {
		problems = append(problems, "P-11: "+err.Error())
	}

	sticky, err = policy.Bool(agentID, control, "P-03")
	if err != nil {
		problems = append(problems, "P-03: "+err.Error())
	}

	values, err := policy.List(agentID, control, "P-07")
	if err != nil {
		problems = append(problems, "P-07: "+err.Error())
	} else {
		umask = values[0]
	}

	return scope, exceptions, sticky, umask, joinProblems(problems)
}

// ev05Params reads P-05 (only its presence: the model is declarative),
// P-09 (usuario column) and P-12.
func ev05Params(policy params.Lister, agentID string) (groups, declared []string, problem string) {

	var problems []string

	if _, err := policy.List(agentID, control, "P-05"); err != nil {
		problems = append(problems, "P-05: "+err.Error())
	}

	declared, err := policy.ListColumn(agentID, control, "P-09", 0)
	if err != nil {
		problems = append(problems, "P-09: "+err.Error())
	}

	groups, err = policy.List(agentID, control, "P-12")
	if err != nil {
		problems = append(problems, "P-12: "+err.Error())
	}

	return groups, declared, joinProblems(problems)
}

func joinProblems(problems []string) string {
	out := ""
	for i, p := range problems {
		if i > 0 {
			out += "; "
		}
		out += p
	}
	return out
}

package opacc5

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Facts is what op.acc.5 reads (source.Source in production).
type Facts interface {
	ServiceLogSnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.ServiceLogSnapshot, error)
	ServiceLogs(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ServiceLog, error)
	ServiceSpans(ctx context.Context, agentID string) (map[string]source.ServiceSpan, error)
	ServiceEvents(ctx context.Context, agentID string, since time.Time, tipos []string, match map[string][]string) ([]source.ServiceEvent, error)
	ServiceMethods(ctx context.Context, agentID string, since time.Time) ([]source.MethodCount, error)
	ServiceCertificates(ctx context.Context, agentID string, since time.Time) ([]source.CertificateCount, error)
	ServiceFailureBursts(ctx context.Context, agentID string, since time.Time, field string, span time.Duration) ([]source.Burst, error)
	ServiceMessages(ctx context.Context, agentID string, since time.Time) ([]source.MessageCount, error)
	ServiceAccounts(ctx context.Context, agentID string) ([]source.ServiceAccount, error)
}

const control = "op.acc.5"

// maxLogPasses is how many reads of the service logs of the window are
// compared for continuity: an hourly agent makes 26 in the default window.
const maxLogPasses = 30

// Evaluator judges op.acc.5.
type Evaluator struct {
	facts Facts

	pass      evaluator.Pass
	snapshots map[string][]fact.ServiceLogSnapshot
	decisions map[string]map[string]verdict.Judgement
}

// NewEvaluator returns the op.acc.5 evaluator.
func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

// Control is the catalog id.
func (e *Evaluator) Control() string { return control }

// Begin reads the service log snapshots of the window, for every agent.
func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {

	e.pass = pass
	e.decisions = map[string]map[string]verdict.Judgement{}

	var err error
	if e.snapshots, err = e.facts.ServiceLogSnapshots(ctx, pass.WindowStart, maxLogPasses); err != nil {
		return fmt.Errorf("service log snapshots: %w", err)
	}

	return nil
}

// Decisions are the requirement decisions taken in Agent.
func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

// Agent judges the nine evidences of op.acc.5 and takes the requirement
// decisions. A read that fails leaves out the evidences that need it.
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

	window, now := e.pass.WindowStart, e.pass.Now

	// Parameters.
	maxAttempts, attemptsProblem := intParam(policy, agent.ID, "P-03")
	rows, err := policy.List(agent.ID, control, "P-02")
	if err != nil && !errors.Is(err, params.ErrNotSet) {
		read("P-02", err)
	}
	declared := declaredNames(rows)

	// What the agent reads, and what the index keeps.
	logPasses, err := e.logPasses(ctx, agent.ID)
	read("logs", err)
	spans, err := e.facts.ServiceSpans(ctx, agent.ID)
	read("events", err)

	var newestLogs []fact.ServiceLog
	runID := ""
	if n := len(logPasses); n > 0 {
		newestLogs, runID = logPasses[n-1].Logs, logPasses[n-1].Snapshot.RecordsRun()
	}
	services := Services(declared, newestLogs, spans)

	policyEvents, err := e.facts.ServiceEvents(ctx, agent.ID, time.Time{}, []string{"politica"}, nil)
	read("events", err)
	policies := Policies(policyEvents)

	judge := func(id string, needs []string, j func() evaluator.Result) {
		for _, n := range needs {
			if failed[n] {
				return
			}
		}
		results[id] = j()
	}

	// EV-01: retention.
	judge("EV-01", []string{"logs", "events"}, func() evaluator.Result {
		in := EV01Input{Services: services, Now: now}
		in.MinDays, in.MinDaysProblem = intParam(policy, agent.ID, "P-08")
		return evaluator.Result{Judgement: JudgeEV01(in), RunID: runID}
	})

	// EV-02: lockout, from the declared policy and the runs of failures of
	// the accounts that failed more than P-03 times in the window.
	judge("EV-02", []string{"logs", "events"}, func() evaluator.Result {
		in := EV02Input{Services: services, Policies: policies, MaxAttempts: maxAttempts, MaxAttemptsProblem: attemptsProblem}
		if attemptsProblem == "" {
			events, err := e.suspects(ctx, agent.ID, window, "usuario", maxAttempts, []string{"autenticacion", "bloqueo", "desbloqueo"})
			if err != nil {
				read("streaks", err)
				return evaluator.Result{Judgement: notRead(err)}
			}
			in.Events = events
		}
		return evaluator.Result{Judgement: JudgeEV02(in)}
	})

	// EV-03: failures by origin.
	judge("EV-03", []string{"logs", "events"}, func() evaluator.Result {
		in := EV03Input{Services: services, Reaching: reaching(services), MaxAttempts: maxAttempts, MaxAttemptsProblem: attemptsProblem}
		if attemptsProblem == "" {
			bursts, err := e.facts.ServiceFailureBursts(ctx, agent.ID, window, "data.origen", originSpan)
			if err != nil {
				read("bursts", err)
				return evaluator.Result{Judgement: notRead(err)}
			}
			in.Bursts = bursts
			var origins []string
			for _, b := range bursts {
				if b.AtMost > maxAttempts {
					origins = append(origins, b.Key)
				}
			}
			if len(origins) > 0 {
				events, err := e.facts.ServiceEvents(ctx, agent.ID, window, []string{"autenticacion"}, map[string][]string{"origen": origins, "resultado": {"fallo"}})
				if err != nil {
					read("bursts", err)
					return evaluator.Result{Judgement: notRead(err)}
				}
				in.Failures = events
			}
		}
		return evaluator.Result{Judgement: JudgeEV03(in)}
	})

	// EV-04: credential age.
	judge("EV-04", []string{"logs", "events"}, func() evaluator.Result {
		in := EV04Input{Services: services, Now: now}
		in.MaxAge, in.MaxAgeProblem = intParam(policy, agent.ID, "P-05")
		accounts, err := e.facts.ServiceAccounts(ctx, agent.ID)
		if err != nil {
			read("accounts", err)
			return evaluator.Result{Judgement: notRead(err)}
		}
		in.Accounts = accounts
		return evaluator.Result{Judgement: JudgeEV04(in)}
	})

	// EV-05: disablement after a notice.
	judge("EV-05", []string{"logs", "events"}, func() evaluator.Result {
		in := EV05Input{Services: services, Now: now}
		in.MaxHours, in.MaxHoursProblem = intParam(policy, agent.ID, "P-06")
		events, err := e.facts.ServiceEvents(ctx, agent.ID, time.Time{}, []string{"notificacion_compromiso", "fin_relacion", "inhabilitacion"}, nil)
		if err != nil {
			read("notices", err)
			return evaluator.Result{Judgement: notRead(err)}
		}
		in.Events = events
		return evaluator.Result{Judgement: JudgeEV05(in)}
	})

	// EV-06: rejection messages.
	judge("EV-06", []string{"logs", "events"}, func() evaluator.Result {
		in := EV06Input{Services: services, EverLogged: map[string]bool{}}
		messages, err := e.facts.ServiceMessages(ctx, agent.ID, window)
		if err == nil {
			var ever []source.MessageCount
			ever, err = e.facts.ServiceMessages(ctx, agent.ID, time.Time{})
			for _, m := range ever {
				in.EverLogged[m.Service] = true
			}
		}
		if err != nil {
			read("messages", err)
			return evaluator.Result{Judgement: notRead(err)}
		}
		in.Messages = messages
		return evaluator.Result{Judgement: JudgeEV06(in)}
	})

	// EV-07: mechanism used.
	mechanism, mechanismProblem := Mechanism(policy.List(agent.ID, control, "P-01"))
	judge("EV-07", []string{"logs", "events"}, func() evaluator.Result {
		in := EV07Input{Services: services, Mechanism: mechanism}
		methods, err := e.facts.ServiceMethods(ctx, agent.ID, window)
		if err != nil {
			read("methods", err)
			return evaluator.Result{Judgement: notRead(err)}
		}
		in.Methods = methods
		return evaluator.Result{Judgement: JudgeEV07(in)}
	})

	// EV-08: certificate validation, only under a certificate mechanism.
	judge("EV-08", []string{"logs", "events"}, func() evaluator.Result {
		if mechanism != "" && mechanism != "R3" && mechanism != "R4" {
			return evaluator.Result{Judgement: verdict.Judgement{Status: verdict.NotApplicable, Reason: "certificates are judged with R3 or R4; P-01 is " + mechanism}}
		}
		in := EV08Input{Services: services}
		in.Rows, in.RowsProblem = listParam(policy, agent.ID, "P-07")
		certs, err := e.facts.ServiceCertificates(ctx, agent.ID, window)
		if err != nil {
			read("certificates", err)
			return evaluator.Result{Judgement: notRead(err)}
		}
		in.Certificates = certs
		return evaluator.Result{Judgement: JudgeEV08(in)}
	})

	// EV-09: continuity.
	judge("EV-09", []string{"logs", "events"}, func() evaluator.Result {
		return evaluator.Result{Judgement: JudgeEV09(EV09Input{Services: services, Passes: logPasses}), RunID: runID}
	})

	// The requirement decisions, with the evidence verdicts known.
	in := DecisionInput{Level: policy.Level(), Mechanism: mechanism, MechanismProblem: mechanismProblem, Policies: policies, Services: services, Evidence: map[string]verdict.Judgement{}}
	for id, r := range results {
		in.Evidence[id] = r.Judgement
	}
	_, in.ProcedureProblem = listParam(policy, agent.ID, "P-04")
	if v, err := policy.Bool(agent.ID, control, "P-09"); err != nil {
		in.LastAccessProblem = err.Error()
	} else {
		in.LastAccess = v
	}
	if rows, err := policy.List(agent.ID, control, "P-DA"); err == nil {
		in.Exclusion = ParseExclusion(rows)
	}

	var requirements []string
	if c, ok := catalog.LookupControl(control); ok {
		for _, r := range c.Requirements {
			requirements = append(requirements, r.ID)
		}
	}
	e.decisions[agent.ID] = Decisions(in, requirements)

	return results, errors.Join(errs...)
}

// logPasses reads the complete service log reads of the window, oldest
// first.
func (e *Evaluator) logPasses(ctx context.Context, agentID string) ([]LogPass, error) {

	snapshots := e.snapshots[agentID]
	var out []LogPass

	// Snapshots come newest first.
	for i := len(snapshots) - 1; i >= 0; i-- {

		s := snapshots[i]
		if s.Status != fact.SourceRead {
			continue
		}

		logs, err := e.facts.ServiceLogs(ctx, agentID, s.RecordsRun(), e.pass.LookbackStart)
		if err != nil {
			return nil, err
		}

		if len(logs) >= s.RecordsEmitted {
			out = append(out, LogPass{Snapshot: s, Logs: logs})
		}
	}

	return out, nil
}

// suspects returns the events of the window of the accounts (or origins)
// whose failures in it exceed limit.
func (e *Evaluator) suspects(ctx context.Context, agentID string, since time.Time, field string, limit int, tipos []string) ([]source.ServiceEvent, error) {

	bursts, err := e.facts.ServiceFailureBursts(ctx, agentID, since, "data."+field, 24*time.Hour)
	if err != nil {
		return nil, err
	}

	var keys []string
	for _, b := range bursts {
		if b.Total > limit {
			keys = append(keys, b.Key)
		}
	}

	if len(keys) == 0 {
		return nil, nil
	}

	return e.facts.ServiceEvents(ctx, agentID, since, tipos, map[string][]string{field: keys})
}

// reaching: the services whose newest line is in Wazuh.
func reaching(services []Service) map[string]bool {

	out := map[string]bool{}

	for _, s := range services {
		if s.Log == nil || s.Log.Status != fact.SourceRead || s.Span.Count == 0 {
			continue
		}
		modified, err := time.Parse(time.RFC3339, s.Log.Modified)
		if err == nil && modified.Sub(s.Span.Newest) <= deliveryLag {
			out[s.Name] = true
		}
	}

	return out
}

func notRead(err error) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseCollection, Reason: err.Error()}
}

func listParam(policy params.Lister, agentID, id string) ([]string, string) {
	values, err := policy.List(agentID, control, id)
	if err != nil {
		return nil, err.Error()
	}
	return values, ""
}

func intParam(policy params.Lister, agentID, id string) (int, string) {

	n, err := policy.Number(agentID, control, id)
	if err != nil {
		return 0, err.Error()
	}
	if n < 0 || n != float64(int(n)) {
		return 0, fmt.Sprintf("%v is not a whole number of zero or more", n)
	}

	return int(n), ""
}

// Package run is one evaluation pass: list the agents, let every control
// judge its evidences, then write evidence, requirement and control verdicts.
package run

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/aggregate"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Agents lists the agents to judge (source.Source in production).
type Agents interface {
	Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
	RegisteredAgents(ctx context.Context, since time.Time) ([]verdict.Agent, error)
}

// Sink is where verdicts go (store.Verdicts in production).
type Sink interface {
	Write(ctx context.Context, v verdict.Verdict) error
}

// Config holds the engine-side parameters of a pass.
type Config struct {
	// Window: only facts newer than this count for a verdict.
	Window time.Duration
	// Lookback: agents with any fact this recent are judged, so an agent
	// that stopped sending gets NOT_EVALUABLE instead of disappearing.
	Lookback      time.Duration
	EngineVersion string
}

// Once judges every known agent with every control and writes the evidence,
// requirement and control verdicts. A failure on one agent, evidence or
// control does not stop the others; all failures are returned together.
func Once(ctx context.Context, agentList Agents, controls []evaluator.Evaluator, policy params.Lister, sink Sink, cfg Config, now time.Time) (int, error) {

	pass := evaluator.Pass{Now: now, WindowStart: now.Add(-cfg.Window), LookbackStart: now.Add(-cfg.Lookback)}

	agents, err := judgedAgents(ctx, agentList, pass.LookbackStart)

	if err != nil {
		return 0, err
	}

	var errs []error
	written := 0

	store := func(v verdict.Verdict) {
		if err := sink.Write(ctx, v); err != nil {
			errs = append(errs, fmt.Errorf("agent %s %s %s %s%s: write: %w", v.Agent.ID, v.Control, v.Scope, v.Requirement, v.Evidence, err))
			return
		}
		written++
	}

	for _, ev := range controls {

		control, ok := catalog.LookupControl(ev.Control())
		if !ok {
			errs = append(errs, fmt.Errorf("%s: not in the catalog", ev.Control()))
			continue
		}

		// A control that cannot read its facts at all still writes verdicts:
		// every evidence becomes a COLLECTION gap.
		begun := true
		if err := ev.Begin(ctx, pass); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", control.Control, err))
			begun = false
		}

		base := func(agent verdict.Agent, scope string) verdict.Verdict {
			return verdict.Verdict{
				OSComplianceVerdict: verdict.SchemaVersion,
				Timestamp:           now.UTC().Format(time.RFC3339),
				Scope:               scope,
				Control:             control.Control,
				Agent:               agent,
				WindowStart:         pass.WindowStart.UTC().Format(time.RFC3339),
				WindowEnd:           now.UTC().Format(time.RFC3339),
				EngineVersion:       cfg.EngineVersion,
			}
		}

		for _, agent := range agents {

			results := map[string]evaluator.Result{}
			var decisions map[string]verdict.Judgement
			if begun {
				var err error
				if results, err = ev.Agent(ctx, agent, policy); err != nil {
					errs = append(errs, fmt.Errorf("%s agent %s: %w", control.Control, agent.ID, err))
				}
				if d, ok := ev.(evaluator.Decider); ok {
					decisions = d.Decisions(agent.ID)
				}
			}

			// The final evidence verdicts, in catalog order, for the
			// requirements. Applicability rules over any judgement; an
			// evidence without a result is not written.
			evidences := map[string]verdict.Judgement{}

			for _, e := range control.Evidences {

				r, judged := results[e.ID]
				na, notApp := notApplicable(policy, control, e.ID)

				switch {
				case notApp:
					r.Judgement = na
				case !judged:
					continue
				}

				evidences[e.ID] = r.Judgement

				v := base(agent, verdict.ScopeEvidence)
				v.Evidence, v.Status, v.Cause, v.Reason, v.RunID = e.ID, r.Judgement.Status, r.Judgement.Cause, r.Judgement.Reason, r.RunID
				store(v)
			}

			// Requirements and control, from whatever evidence verdicts exist:
			// an evidence that could not be judged counts as a COLLECTION gap.
			for _, v := range aggregateVerdicts(policy, control, agent, evidences, decisions, base) {
				store(v)
			}
		}
	}

	return written, errors.Join(errs...)
}

// judgedAgents is every agent with facts in the lookback plus every agent
// Wazuh has registered (and the manager): a silent agent keeps getting
// verdicts instead of disappearing.
func judgedAgents(ctx context.Context, list Agents, since time.Time) ([]verdict.Agent, error) {

	senders, err := list.Agents(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("agents: %w", err)
	}

	registered, err := list.RegisteredAgents(ctx, since)
	if err != nil {
		return nil, fmt.Errorf("registered agents: %w", err)
	}

	seen := map[string]int{}
	var agents []verdict.Agent

	for _, a := range append(senders, registered...) {
		if i, ok := seen[a.ID]; ok {
			if agents[i].Name == "" {
				agents[i].Name = a.Name
			}
			continue
		}
		seen[a.ID] = len(agents)
		agents = append(agents, a)
	}

	return agents, nil
}

// aggregateVerdicts builds the requirement and control verdicts of one agent.
func aggregateVerdicts(policy params.Lister, control catalog.Control, agent verdict.Agent, evidences, decisions map[string]verdict.Judgement, base func(verdict.Agent, string) verdict.Verdict) []verdict.Verdict {

	level := policy.Level()
	enabled := policy.ControlEnabled(control.Control)

	rows, _ := policy.List(agent.ID, control.Control, "P-ATT")
	attestations := aggregate.ParseAttestations(rows)

	var out []verdict.Verdict
	var reqs []aggregate.Requirement

	for _, req := range control.Requirements {

		var att *aggregate.Attestation
		if a, ok := attestations[req.ID]; ok {
			att = &a
		}

		r := aggregate.EvaluateRequirement(req, level, enabled, evidences, att)

		// The control's own decision, where the requirement applies at all.
		if d, ok := decisions[req.ID]; ok && r.Status != verdict.NotApplicable {
			r = aggregate.FromDecision(req.ID, d)
		}
		reqs = append(reqs, r)

		v := base(agent, verdict.ScopeRequirement)
		v.Requirement, v.Status, v.Reason, v.Attested = req.ID, r.Status, r.Reason, r.Attested
		if r.Status != verdict.NotApplicable {
			evidenced := r.Evidenced
			v.Evidenced = &evidenced
		}
		out = append(out, v)
	}

	c := aggregate.EvaluateControl(reqs)

	v := base(agent, verdict.ScopeControl)
	v.Status, v.Score = c.Status, c.Score

	if c.Status == verdict.NotApplicable {
		v.Reason = "no requirement applies"
		if !enabled {
			v.Reason = "control disabled in the configuration"
		}
	} else {
		coverage, applicable, measured := c.Coverage, c.Applicable, c.Measured
		v.Coverage, v.ApplicableRequirements, v.MeasuredRequirements = &coverage, &applicable, &measured
		v.UnmeasuredRequirements = c.Unmeasured
		v.Reason = fmt.Sprintf("%d of %d applicable requirements compliant, %d measured", countCompliant(reqs), applicable, measured)
	}

	return append(out, v)
}

func countCompliant(reqs []aggregate.Requirement) int {
	n := 0
	for _, r := range reqs {
		if r.Status == verdict.Compliant {
			n++
		}
	}
	return n
}

// notApplicable decides, before any judgement counts, whether the evidence
// applies at all: the engine decides it, from the configuration's level and
// the catalog's evidence levels. Without a known level nothing is ruled out.
func notApplicable(policy params.Lister, control catalog.Control, evidenceID string) (verdict.Judgement, bool) {

	if !policy.ControlEnabled(control.Control) {
		return verdict.Judgement{Status: verdict.NotApplicable, Reason: control.Control + " is disabled in the configuration"}, true
	}

	level := policy.Level()
	evidence, known := control.Evidence(evidenceID)

	if level == "" || !known || evidence.AppliesAt(level) {
		return verdict.Judgement{}, false
	}

	return verdict.Judgement{
		Status: verdict.NotApplicable,
		Reason: fmt.Sprintf("%s applies at %s; active ENS level %s", evidenceID, strings.Join(evidence.Levels, ", "), level),
	}, true
}

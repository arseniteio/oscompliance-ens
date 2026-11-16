package mpcom4

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Facts interface {
	Networks(ctx context.Context, tools []string) (map[string]*source.Network, error)
	FleetReporting(ctx context.Context, since time.Time) (map[string]source.Reporting, error)
	SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error)
	AcceptedFlows(ctx context.Context, names []string, since time.Time) ([]source.Flow, error)
}

const control = "mp.com.4"

var modalityRequirement = map[string]string{VLAN: "mp.com.4.r1.1", VPN: "mp.com.4.r2.1", Physical: "mp.com.4.r3.1"}

type Evaluator struct {
	facts Facts

	pass      evaluator.Pass
	networks  map[string]*source.Network
	names     map[string]string
	hours     map[string][]time.Time
	flows     map[string][]source.Flow
	decisions map[string]map[string]verdict.Judgement
}

func NewEvaluator(facts Facts) *Evaluator {
	return &Evaluator{facts: facts}
}

func (e *Evaluator) Control() string { return control }

func (e *Evaluator) Begin(ctx context.Context, pass evaluator.Pass) error {
	e.pass = pass
	e.hours, e.flows, e.names = map[string][]time.Time{}, map[string][]source.Flow{}, map[string]string{}
	e.decisions = map[string]map[string]verdict.Judgement{}
	var err error
	if e.networks, err = e.facts.Networks(ctx, mpcom1.TunnelTools); err != nil {
		return fmt.Errorf("networks: %w", err)
	}
	reporting, err := e.facts.FleetReporting(ctx, pass.LookbackStart)
	if err != nil {
		return fmt.Errorf("reporting: %w", err)
	}
	for id, r := range reporting {
		e.names[strings.ToLower(r.Name)] = id
	}
	return nil
}

func (e *Evaluator) Decisions(agentID string) map[string]verdict.Judgement {
	return e.decisions[agentID]
}

func Modality(v string) string {
	switch m := strings.ReplaceAll(opcont2.Person(v), " ", "_"); {
	case strings.HasPrefix(m, "vlan") || m == "r1":
		return VLAN
	case strings.HasPrefix(m, "vpn") || m == "r2":
		return VPN
	case strings.HasPrefix(m, "fisic") || strings.HasPrefix(m, "medios") || m == "r3":
		return Physical
	default:
		return m
	}
}

func (e *Evaluator) Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]evaluator.Result, error) {

	now := e.pass.Now
	results := map[string]evaluator.Result{}
	put := func(id string, j verdict.Judgement) { results[id] = evaluator.Result{Judgement: j} }
	gap := func(m catalog.Message) verdict.Judgement { return passes.Gap(verdict.CauseConfiguration, m) }
	list := func(controlID, id string, optional bool) ([]string, catalog.Message) {
		rows, err := policy.List(agent.ID, controlID, id)
		if err != nil && !(optional && errors.Is(err, params.ErrNotSet)) {
			return nil, passes.Param(id, err)
		}
		return rows, catalog.Message{}
	}

	segmentRows, segmentsProblem := list(control, "P-01", false)
	segments := ParseSegments(segmentRows)
	network := e.networks[agent.ID]
	withSegments := func(judge func() verdict.Judgement) verdict.Judgement {
		if !segmentsProblem.IsZero() {
			return gap(segmentsProblem)
		}
		return judge()
	}

	modalityRows, modalityProblem := list(control, "P-03", false)
	modality := ""
	vlanAtHigh := false
	if modalityProblem.IsZero() {
		modality = Modality(modalityRows[0])
		vlanAtHigh = modality == VLAN && policy.Level() == "ALTO"
		e.decisions[agent.ID] = map[string]verdict.Judgement{}
		for m, req := range modalityRequirement {
			if m != modality && !vlanAtHigh {
				e.decisions[agent.ID][req] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("mpcom4.modality", "modality", modalityRows[0]))
			}
		}
	}

	points, pointsProblem := list(control, "P-05", true)
	var elements []mpcom1.Element
	for _, r := range points {
		if c := cells(r, 4); c[3] != "" {
			elements = append(elements, mpcom1.Element{Name: c[0], Source: c[3]})
		}
	}
	elements, flows, err := e.activity(ctx, elements)
	if err != nil {
		return nil, fmt.Errorf("interconnection points: %w", err)
	}

	put("EV-01", withSegments(func() verdict.Judgement { return JudgeEV01(segments, network) }))

	put("EV-02", withSegments(func() verdict.Judgement {
		matrix, problem := list(control, "P-02", false)
		if !problem.IsZero() {
			return gap(problem)
		}
		if !pointsProblem.IsZero() {
			return gap(pointsProblem)
		}
		if len(elements) == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("mpcom4.no_points"))
		}
		return JudgeEV02(flows, segments, matrix)
	}))

	put("EV-03", withSegments(func() verdict.Judgement { return JudgeEV03(segments, network, agent.Name, points) }))
	put("EV-04", withSegments(func() verdict.Judgement { return JudgeEV04(segments, network) }))

	put("EV-05", func() verdict.Judgement {
		hours, problem := passes.Whole(policy, agent.ID, control, "P-09", "param.not_hours")
		if !problem.IsZero() {
			return gap(problem)
		}
		return mpcom1.JudgeEV01(elements, hours, now)
	}())

	put("EV-07", withSegments(func() verdict.Judgement {
		if !modalityProblem.IsZero() {
			return gap(modalityProblem)
		}
		if vlanAtHigh {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.vlan_at_high"))
		}
		return JudgeEV07(modality, segments, network)
	}))

	put("EV-08", withSegments(func() verdict.Judgement { return JudgeEV08(segments) }))

	put("EV-09", withSegments(func() verdict.Judgement {
		rows, problem := list(opexp7.Control, opexp7.RegisterParam, true)
		if !problem.IsZero() {
			return gap(problem)
		}
		var incidents []opexp7.Incident
		for _, in := range opexp7.ParseRegister(rows) {
			if !in.Opened().Before(now.Add(-opexp7.Horizon)) {
				incidents = append(incidents, in)
			}
		}
		return JudgeEV09(incidents, func(machine string) []string {
			in, _ := SegmentsOf(segments, e.networks[e.names[strings.ToLower(machine)]])
			return in
		})
	}))

	put("EV-10", func() verdict.Judgement {
		reviews, problem := list(control, "P-08", false)
		days, daysProblem := passes.Whole(policy, agent.ID, control, "P-07", "param.not_days")
		j, _ := passes.Review(reviews, problem, "P-08", days, daysProblem, "P-07", now)
		return j
	}())

	return results, nil
}

func (e *Evaluator) activity(ctx context.Context, elements []mpcom1.Element) ([]mpcom1.Element, []source.Flow, error) {

	var names []string
	for i, el := range elements {
		h, ok := e.hours[el.Source]
		if !ok {
			var err error
			if h, err = e.facts.SourceActivity(ctx, el.Source, e.pass.Now.Add(-7*24*time.Hour)); err != nil {
				return nil, nil, err
			}
			e.hours[el.Source] = h
		}
		elements[i].Hours = h
		names = append(names, el.Source)
	}
	key := fmt.Sprint(names)
	flows, ok := e.flows[key]
	if !ok {
		var err error
		if flows, err = e.facts.AcceptedFlows(ctx, names, e.pass.WindowStart); err != nil {
			return nil, nil, err
		}
		e.flows[key] = flows
	}
	return elements, flows, nil
}

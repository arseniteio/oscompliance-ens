package run

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type fakeAgents struct {
	senders, registered []verdict.Agent
}

func (f fakeAgents) Agents(context.Context, time.Time) ([]verdict.Agent, error) {
	return f.senders, nil
}

func (f fakeAgents) RegisteredAgents(context.Context, time.Time) ([]verdict.Agent, error) {
	return f.registered, nil
}

type fakeControl struct {
	beginErr error
	results  map[string]map[string]evaluator.Result
	failing  map[string]bool
}

func (f *fakeControl) Control() string { return "op.acc.1" }

func (f *fakeControl) Begin(context.Context, evaluator.Pass) error { return f.beginErr }

func (f *fakeControl) Agent(_ context.Context, agent verdict.Agent, _ params.Lister) (map[string]evaluator.Result, error) {
	if f.failing[agent.ID] {
		return map[string]evaluator.Result{"EV-03": compliant()}, errors.New("boom")
	}
	return f.results[agent.ID], nil
}

func compliant() evaluator.Result {
	return evaluator.Result{Judgement: verdict.Judgement{Status: verdict.Compliant}}
}

func allCompliant() map[string]evaluator.Result {
	out := map[string]evaluator.Result{}
	for _, id := range []string{"EV-01", "EV-02", "EV-03", "EV-04", "EV-05", "EV-06", "EV-07", "EV-08"} {
		out[id] = compliant()
	}
	return out
}

type fakeSink struct{ got []verdict.Verdict }

func (s *fakeSink) Write(_ context.Context, v verdict.Verdict) error {
	s.got = append(s.got, v)
	return nil
}

type noParams struct {
	level    string
	disabled bool
}

func (noParams) List(string, string, string) ([]string, error) { return nil, params.ErrNotSet }

func (noParams) ListColumn(string, string, string, int) ([]string, error) {
	return nil, params.ErrNotSet
}

func (noParams) Number(string, string, string) (float64, error) { return 0, params.ErrNotSet }

func (noParams) Bool(string, string, string) (bool, error) { return false, params.ErrNotSet }

func (noParams) Matcher(string, string, string) (params.Matcher, error) {
	return params.Matcher{}, params.ErrNotSet
}

func (p noParams) Level() string { return p.level }

func (p noParams) ControlEnabled(string) bool { return !p.disabled }

var cfg = Config{Window: 26 * time.Hour, Lookback: 168 * time.Hour, EngineVersion: "test"}

func index(got []verdict.Verdict) map[string]verdict.Verdict {
	out := map[string]verdict.Verdict{}
	for _, v := range got {
		out[v.Agent.ID+" "+v.Scope+" "+v.Requirement+v.Evidence] = v
	}
	return out
}

func TestOnceWritesEveryScope(t *testing.T) {
	control := &fakeControl{
		results: map[string]map[string]evaluator.Result{"001": allCompliant()},
		failing: map[string]bool{"002": true},
	}
	sink := &fakeSink{}
	now := time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)

	n, err := Once(context.Background(), fakeAgents{senders: []verdict.Agent{{ID: "001", Name: "a"}, {ID: "002", Name: "b"}}}, []evaluator.Evaluator{control}, noParams{level: "MEDIO"}, sink, cfg, now)

	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("want the read error of 002, got %v", err)
	}

	if n != 17+10 {
		t.Fatalf("want 27 verdicts, got %d", n)
	}

	got := index(sink.got)

	if v := got["001 evidence EV-01"]; v.Control != "op.acc.1" || v.WindowStart != "2026-10-20T14:00:00Z" || v.WindowEnd != "2026-10-21T16:00:00Z" || v.Agent.Name != "a" {
		t.Errorf("001 EV-01: %+v", v)
	}

	if v := got["001 control "]; v.Status != verdict.Partial || v.Score == nil || *v.Score != 75 {
		t.Errorf("001 control: %+v", v)
	}

	if v := got["002 requirement op.acc.1.4"]; v.Status != verdict.NonCompliant || v.Evidenced == nil || *v.Evidenced || !strings.Contains(v.Reason, "EV-01 (COLLECTION)") {
		t.Errorf("002 op.acc.1.4: %+v", v)
	}
	if _, ok := got["002 evidence EV-01"]; ok {
		t.Error("an evidence without a result must not be written")
	}
}

func TestOnceControlBeginFails(t *testing.T) {
	control := &fakeControl{beginErr: errors.New("indexer down")}
	sink := &fakeSink{}

	_, err := Once(context.Background(), fakeAgents{senders: []verdict.Agent{{ID: "001"}}}, []evaluator.Evaluator{control}, noParams{}, sink, cfg, time.Now())

	if err == nil {
		t.Error("want the Begin error")
	}
	got := index(sink.got)
	if v := got["001 control "]; v.Status != verdict.NonCompliant || v.MeasuredRequirements == nil || *v.MeasuredRequirements != 0 {
		t.Errorf("control: %+v", v)
	}
}

func TestOnceJudgesRegisteredSilentAgents(t *testing.T) {
	agents := fakeAgents{
		senders:    []verdict.Agent{{ID: "001"}},
		registered: []verdict.Agent{{ID: "001", Name: "web"}, {ID: "002", Name: "silent"}, {ID: "000", Name: "wazuh.manager"}},
	}
	control := &fakeControl{results: map[string]map[string]evaluator.Result{"001": allCompliant()}}
	sink := &fakeSink{}

	if _, err := Once(context.Background(), agents, []evaluator.Evaluator{control}, noParams{}, sink, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}

	byAgent := map[string]int{}
	names := map[string]string{}
	for _, v := range sink.got {
		byAgent[v.Agent.ID]++
		names[v.Agent.ID] = v.Agent.Name
	}

	if byAgent["001"] != 17 || byAgent["002"] != 9 || byAgent["000"] != 9 {
		t.Errorf("verdicts by agent: %v", byAgent)
	}
	if names["001"] != "web" {
		t.Errorf("name of 001: %q", names["001"])
	}
}

func TestOnceNotApplicable(t *testing.T) {
	control := &fakeControl{results: map[string]map[string]evaluator.Result{"001": allCompliant()}}
	agents := fakeAgents{senders: []verdict.Agent{{ID: "001"}}}

	run := func(policy noParams) map[string]verdict.Verdict {
		sink := &fakeSink{}
		if _, err := Once(context.Background(), agents, []evaluator.Evaluator{control}, policy, sink, cfg, time.Now()); err != nil {
			t.Fatal(err)
		}
		return index(sink.got)
	}

	bajo := run(noParams{level: "BAJO"})
	if v := bajo["001 evidence EV-07"]; v.Status != verdict.NotApplicable || !strings.Contains(v.Reason, "MEDIO, ALTO") {
		t.Errorf("EV-07 at BAJO: %+v", v)
	}
	if v := bajo["001 requirement op.acc.1.r1.3"]; v.Status != verdict.NotApplicable {
		t.Errorf("r1.3 at BAJO: %+v", v)
	}
	if v := bajo["001 evidence EV-01"]; v.Status != verdict.Compliant {
		t.Errorf("EV-01 at BAJO: %+v", v)
	}

	if v := run(noParams{level: "MEDIO"})["001 evidence EV-07"]; v.Status != verdict.Compliant {
		t.Errorf("EV-07 at MEDIO: %+v", v)
	}

	for key, v := range run(noParams{level: "ALTO", disabled: true}) {
		if v.Status != verdict.NotApplicable || !strings.Contains(v.Reason, "disabled") {
			t.Errorf("%s with op.acc.1 disabled: %+v", key, v)
		}
	}
}

type orderControl struct {
	id, after string
	log       *[]string
	mu        *sync.Mutex
}

func (c *orderControl) Control() string { return c.id }

func (c *orderControl) After() []string {
	if c.after == "" {
		return nil
	}
	return []string{c.after}
}

func (c *orderControl) Begin(context.Context, evaluator.Pass) error {
	if c.after == "" {

		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func (c *orderControl) Agent(context.Context, verdict.Agent, params.Lister) (map[string]evaluator.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	*c.log = append(*c.log, c.id)
	return nil, nil
}

func TestOnceFollowerWaits(t *testing.T) {

	var log []string
	var mu sync.Mutex
	controls := []evaluator.Evaluator{
		&orderControl{id: "op.acc.6", after: "op.acc.1", log: &log, mu: &mu},
		&orderControl{id: "op.acc.1", log: &log, mu: &mu},
	}
	agents := fakeAgents{senders: []verdict.Agent{{ID: "001"}, {ID: "002"}}}

	if _, err := Once(context.Background(), agents, controls, noParams{}, &fakeSink{}, cfg, time.Now()); err != nil {
		t.Fatal(err)
	}

	if strings.Join(log, " ") != "op.acc.1 op.acc.1 op.acc.6 op.acc.6" {
		t.Fatalf("order: %v", log)
	}
}

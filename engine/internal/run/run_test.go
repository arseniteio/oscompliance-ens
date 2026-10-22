package run

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

type fakeFacts struct {
	agents []verdict.Agent

	currentIdentity map[string][]fact.IdentitySnapshot
	earlierIdentity map[string][]fact.IdentitySnapshot
	identityRecords map[string][]fact.IdentityRecord // by run_id
	identityAsked   []string
	failIdentityRun string
}

func (f *fakeFacts) Logins(context.Context, string, time.Time) ([]source.Login, error) {
	return nil, nil
}

func (f *fakeFacts) AuthActivity(context.Context, time.Time) (map[string]time.Time, error) {
	return nil, nil
}

func (f *fakeFacts) GroupSnapshots(context.Context, time.Time) (map[string]fact.GroupSnapshot, error) {
	return nil, nil
}

func (f *fakeFacts) GroupRecords(context.Context, string, string, time.Time) ([]fact.GroupRecord, error) {
	return nil, nil
}

type memHistory struct{ saved []history.Account }

func (m *memHistory) Load(context.Context, string) (map[string]history.Account, error) {
	return map[string]history.Account{}, nil
}

func (m *memHistory) Save(_ context.Context, accounts []history.Account) error {
	m.saved = append(m.saved, accounts...)
	return nil
}

// noParams: no parameter set, level as given, every control enabled.
type noParams struct {
	level    string
	disabled bool
}

func (p noParams) Level() string { return p.level }

func (p noParams) ControlEnabled(string) bool { return !p.disabled }

func (noParams) List(string, string, string) ([]string, error) { return nil, params.ErrNotSet }

func (noParams) ListColumn(string, string, string, int) ([]string, error) {
	return nil, params.ErrNotSet
}

func (noParams) Number(string, string, string) (float64, error) { return 0, params.ErrNotSet }

func (noParams) Matcher(string, string, string) (params.Matcher, error) {
	return params.Matcher{}, params.ErrNotSet
}

func (f *fakeFacts) IdentitySnapshots(_ context.Context, _ time.Time, n int) (map[string][]fact.IdentitySnapshot, error) {
	if n == 1 {
		return f.currentIdentity, nil
	}
	return f.earlierIdentity, nil
}

func (f *fakeFacts) IdentityRecords(_ context.Context, _, runID string, _ time.Time) ([]fact.IdentityRecord, error) {
	f.identityAsked = append(f.identityAsked, runID)
	if runID == f.failIdentityRun {
		return nil, errors.New("boom")
	}
	return f.identityRecords[runID], nil
}

func (f *fakeFacts) Agents(context.Context, time.Time) ([]verdict.Agent, error) {
	return f.agents, nil
}

type fakeSink struct{ got []verdict.Verdict }

func (s *fakeSink) Write(_ context.Context, v verdict.Verdict) error {
	s.got = append(s.got, v)
	return nil
}

func TestOnceWritesOneVerdictPerAgent(t *testing.T) {
	pass := func(run string) []fact.IdentitySnapshot { return []fact.IdentitySnapshot{identityPass(run, 1, true)} }

	facts := &fakeFacts{
		agents: []verdict.Agent{{ID: "001", Name: "a"}, {ID: "002", Name: "b"}, {ID: "003", Name: "c"}},
		currentIdentity: map[string][]fact.IdentitySnapshot{
			"001": pass("r1"),
			"003": pass("r3"),
		},
		identityRecords: map[string][]fact.IdentityRecord{"r1": {{AccountName: "root"}}},
		failIdentityRun: "r3",
	}
	sink := &fakeSink{}
	now := time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)

	n, err := Once(context.Background(), facts, noParams{}, &memHistory{}, sink, Config{Window: 26 * time.Hour, Lookback: 168 * time.Hour, EngineVersion: "test"}, now)

	if err == nil {
		t.Error("want the error of agent 003")
	}

	// 8 evidences for 001 and 002; 003 loses EV-01, EV-02 and EV-07, which
	// read its identity pass, and still gets the other 5.
	if n != 21 || len(sink.got) != 21 {
		t.Fatalf("want 21 verdicts, got %d", n)
	}

	got := map[string]verdict.Verdict{}
	for _, v := range sink.got {
		got[v.Agent.ID+" "+v.Evidence] = v
	}

	if v := got["001 EV-01"]; v.RunID != "r1" || v.Control != "op.acc.1" || v.WindowStart != "2026-10-20T14:00:00Z" || v.WindowEnd != "2026-10-21T16:00:00Z" || v.Agent.Name != "a" {
		t.Errorf("001 EV-01: %+v", v)
	}
	if v := got["002 EV-01"]; v.RunID != "" || v.Status != verdict.NotEvaluable {
		t.Errorf("002 without identity pass: %+v", v)
	}
	for _, ev := range []string{"EV-01", "EV-02", "EV-07"} {
		if _, ok := got["003 "+ev]; ok {
			t.Errorf("003 %s written despite the read error", ev)
		}
	}
}

func identityPass(runID string, emitted int, read bool) fact.IdentitySnapshot {
	s := fact.IdentitySnapshot{Envelope: fact.Envelope{RunID: runID, TS: "2026-10-22T12:00:00Z"}, PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &emitted}
	if !read {
		s.ShadowStatus, s.ShadowError, s.RecordsEmitted = fact.SourceUnreadable, "denied", nil
	}
	return s
}

func TestOncePicksPreviousCompleteIdentityPass(t *testing.T) {
	cur := identityPass("cur", 1, true)
	facts := &fakeFacts{
		agents:          []verdict.Agent{{ID: "001", Name: "a"}},
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {cur}},
		earlierIdentity: map[string][]fact.IdentitySnapshot{"001": {
			cur,                                 // the current pass itself: skipped
			identityPass("unread", 0, false),    // shadow not read: skipped
			identityPass("incomplete", 2, true), // 1 of 2 records: skipped
			identityPass("good", 1, true),       // previous
			identityPass("older", 1, true),      // never reached
		}},
		identityRecords: map[string][]fact.IdentityRecord{
			"cur": {{}}, "incomplete": {{}}, "good": {{}}, "older": {{}},
		},
	}

	if _, err := Once(context.Background(), facts, noParams{}, &memHistory{}, &fakeSink{}, Config{Window: time.Hour, Lookback: 2 * time.Hour}, time.Now()); err != nil {
		t.Fatal(err)
	}

	want := []string{"cur", "incomplete", "good"}
	if len(facts.identityAsked) != len(want) {
		t.Fatalf("records asked for %v, want %v", facts.identityAsked, want)
	}
	for i := range want {
		if facts.identityAsked[i] != want[i] {
			t.Fatalf("records asked for %v, want %v", facts.identityAsked, want)
		}
	}
}

func TestOnceNotApplicable(t *testing.T) {
	facts := &fakeFacts{agents: []verdict.Agent{{ID: "001", Name: "a"}}}
	cfg := Config{Window: time.Hour, Lookback: 2 * time.Hour}

	byEvidence := func(policy noParams) map[string]verdict.Verdict {
		sink := &fakeSink{}
		if _, err := Once(context.Background(), facts, policy, &memHistory{}, sink, cfg, time.Now()); err != nil {
			t.Fatal(err)
		}
		got := map[string]verdict.Verdict{}
		for _, v := range sink.got {
			got[v.Evidence] = v
		}
		return got
	}

	bajo := byEvidence(noParams{level: "BAJO"})
	if v := bajo["EV-07"]; v.Status != verdict.NotApplicable || !strings.Contains(v.Reason, "MEDIO, ALTO") {
		t.Errorf("EV-07 at BAJO: %+v", v)
	}
	if bajo["EV-01"].Status == verdict.NotApplicable {
		t.Errorf("EV-01 applies at BAJO: %+v", bajo["EV-01"])
	}

	if v := byEvidence(noParams{level: "MEDIO"})["EV-07"]; v.Status == verdict.NotApplicable {
		t.Errorf("EV-07 at MEDIO: %+v", v)
	}

	if v := byEvidence(noParams{})["EV-07"]; v.Status == verdict.NotApplicable {
		t.Errorf("EV-07 with no level: %+v", v)
	}

	for ev, v := range byEvidence(noParams{level: "ALTO", disabled: true}) {
		if v.Status != verdict.NotApplicable || !strings.Contains(v.Reason, "disabled") {
			t.Errorf("%s with op.acc.1 disabled: %+v", ev, v)
		}
	}
}

package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

type fakeFacts struct {
	agents    []verdict.Agent
	snapshots map[string]fact.AccountInventorySnapshot
	records   map[string][]fact.AccountRecord // by run_id
	failRun   string
	asked     []string // run_ids asked for

	currentIdentity map[string][]fact.IdentitySnapshot
	earlierIdentity map[string][]fact.IdentitySnapshot
	identityRecords map[string][]fact.IdentityRecord // by run_id
	identityAsked   []string
}

func (f *fakeFacts) SSHLogins(context.Context, string, time.Time) ([]source.Login, error) {
	return nil, nil
}

func (f *fakeFacts) AuthActivity(context.Context, time.Time) (map[string]time.Time, error) {
	return nil, nil
}

type noParams struct{}

func (noParams) List(string, string, string) ([]string, error) { return nil, errors.New("not set") }

func (noParams) ListColumn(string, string, string, int) ([]string, error) {
	return nil, errors.New("not set")
}

func (f *fakeFacts) IdentitySnapshots(_ context.Context, _ time.Time, n int) (map[string][]fact.IdentitySnapshot, error) {
	if n == 1 {
		return f.currentIdentity, nil
	}
	return f.earlierIdentity, nil
}

func (f *fakeFacts) IdentityRecords(_ context.Context, _, runID string, _ time.Time) ([]fact.IdentityRecord, error) {
	f.identityAsked = append(f.identityAsked, runID)
	return f.identityRecords[runID], nil
}

func (f *fakeFacts) Agents(context.Context, time.Time) ([]verdict.Agent, error) {
	return f.agents, nil
}

func (f *fakeFacts) LatestSnapshots(context.Context, time.Time) (map[string]fact.AccountInventorySnapshot, error) {
	return f.snapshots, nil
}

func (f *fakeFacts) AccountRecords(_ context.Context, _, runID string, _ time.Time) ([]fact.AccountRecord, error) {
	f.asked = append(f.asked, runID)
	if runID == f.failRun {
		return nil, errors.New("boom")
	}
	return f.records[runID], nil
}

type fakeSink struct{ got []verdict.Verdict }

func (s *fakeSink) Write(_ context.Context, v verdict.Verdict) error {
	s.got = append(s.got, v)
	return nil
}

func TestOnceWritesOneVerdictPerAgent(t *testing.T) {
	two := 2
	facts := &fakeFacts{
		agents: []verdict.Agent{{ID: "001", Name: "a"}, {ID: "002", Name: "b"}, {ID: "003", Name: "c"}, {ID: "004", Name: "d"}},
		snapshots: map[string]fact.AccountInventorySnapshot{
			"001": {Envelope: fact.Envelope{RunID: "r1"}, SourceStatus: fact.SourceRead, RecordsEmitted: &two, DuplicateUIDs: []fact.DuplicateUID{}},
			"002": {Envelope: fact.Envelope{RunID: "r2"}, SourceStatus: fact.SourceUnreadable, SourceError: "denied"},
			"004": {Envelope: fact.Envelope{RunID: "r4"}, SourceStatus: fact.SourceRead, RecordsEmitted: &two, DuplicateUIDs: []fact.DuplicateUID{}},
		},
		records: map[string][]fact.AccountRecord{"r1": {{}, {}}},
		failRun: "r4",
	}
	sink := &fakeSink{}
	now := time.Date(2026, 10, 21, 16, 0, 0, 0, time.UTC)

	n, err := Once(context.Background(), facts, noParams{}, sink, Config{Window: 26 * time.Hour, Lookback: 168 * time.Hour, EngineVersion: "test"}, now)

	if err == nil {
		t.Error("want the error of agent 004")
	}
	// EV-01 and EV-07 for 001, 002, 003 (004 fails); EV-02, EV-03 and EV-05
	// for all four.
	if n != 18 || len(sink.got) != 18 {
		t.Fatalf("want 18 verdicts, got %d: %+v", n, sink.got)
	}
	// Records are read only for snapshots that were read.
	if len(facts.asked) != 2 || facts.asked[0] != "r1" || facts.asked[1] != "r4" {
		t.Errorf("records asked for %v", facts.asked)
	}

	byAgent := map[string]verdict.Verdict{}
	for _, v := range sink.got {
		if v.Evidence == "EV-01" {
			byAgent[v.Agent.ID] = v
		}
	}
	if byAgent["001"].RunID != "r1" || byAgent["002"].RunID != "r2" || byAgent["003"].RunID != "" {
		t.Errorf("run ids: %+v", byAgent)
	}
	v := byAgent["001"]
	if v.Control != "op.acc.1" || v.Evidence != "EV-01" || v.WindowStart != "2026-10-20T14:00:00Z" || v.WindowEnd != "2026-10-21T16:00:00Z" || v.Agent.Name != "a" {
		t.Errorf("verdict fields: %+v", v)
	}
}

func identityPass(runID string, emitted int, read bool) fact.IdentitySnapshot {
	s := fact.IdentitySnapshot{Envelope: fact.Envelope{RunID: runID}, PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &emitted}
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

	if _, err := Once(context.Background(), facts, noParams{}, &fakeSink{}, Config{Window: time.Hour, Lookback: 2 * time.Hour}, time.Now()); err != nil {
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

package opacc1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/evaluator"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

type fakeFacts struct {
	currentIdentity map[string][]fact.IdentitySnapshot
	earlierIdentity map[string][]fact.IdentitySnapshot
	identityRecords map[string][]fact.IdentityRecord // by run_id
	identityAsked   []string
	failIdentityRun string
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

type noParams struct{}

func (noParams) List(string, string, string) ([]string, error) { return nil, params.ErrNotSet }

func (noParams) ListColumn(string, string, string, int) ([]string, error) {
	return nil, params.ErrNotSet
}

func (noParams) Number(string, string, string) (float64, error) { return 0, params.ErrNotSet }

func (noParams) Matcher(string, string, string) (params.Matcher, error) {
	return params.Matcher{}, params.ErrNotSet
}

func (noParams) Level() string { return "" }

func (noParams) ControlEnabled(string) bool { return true }

func identityPass(runID string, emitted int, read bool) fact.IdentitySnapshot {
	s := fact.IdentitySnapshot{Envelope: fact.Envelope{RunID: runID, TS: "2026-10-22T12:00:00Z"}, PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &emitted}
	if !read {
		s.ShadowStatus, s.ShadowError, s.RecordsEmitted = fact.SourceUnreadable, "denied", nil
	}
	return s
}

func begin(t *testing.T, facts Facts, hist History) *Evaluator {
	t.Helper()
	e := NewEvaluator(facts, hist)
	now := time.Date(2026, 10, 22, 13, 0, 0, 0, time.UTC)
	if err := e.Begin(context.Background(), evaluator.Pass{Now: now, WindowStart: now.Add(-26 * time.Hour), LookbackStart: now.Add(-168 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEvaluatorPicksPreviousCompleteIdentityPass(t *testing.T) {
	cur := identityPass("cur", 1, true)
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {cur}},
		earlierIdentity: map[string][]fact.IdentitySnapshot{"001": {
			cur,                                 // the current pass itself: skipped
			identityPass("unread", 0, false),    // shadow not read: skipped
			identityPass("incomplete", 2, true), // 1 of 2 records: skipped
			identityPass("good", 1, true),       // previous
			identityPass("older", 1, true),      // never reached
		}},
		identityRecords: map[string][]fact.IdentityRecord{
			"cur": {{AccountName: "root"}}, "incomplete": {{}}, "good": {{AccountName: "root"}}, "older": {{}},
		},
	}

	results, err := begin(t, facts, &memHistory{}).Agent(context.Background(), verdict.Agent{ID: "001"}, noParams{})
	if err != nil {
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

	if len(results) != 8 {
		t.Errorf("want 8 evidence results, got %d", len(results))
	}
	if r := results["EV-02"]; r.RunID != "cur" || r.Judgement.Status != verdict.Compliant {
		t.Errorf("EV-02: %+v", r)
	}
}

// A failing identity read loses the evidences that need it, not the others.
func TestEvaluatorKeepsOtherEvidencesOnReadError(t *testing.T) {
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {identityPass("cur", 1, true)}},
		failIdentityRun: "cur",
	}

	results, err := begin(t, facts, &memHistory{}).Agent(context.Background(), verdict.Agent{ID: "001"}, noParams{})
	if err == nil {
		t.Error("want the read error")
	}
	for _, id := range []string{"EV-01", "EV-02", "EV-04", "EV-07", "EV-08"} {
		if _, ok := results[id]; ok {
			t.Errorf("%s judged despite the read error", id)
		}
	}
	for _, id := range []string{"EV-03", "EV-05", "EV-06"} {
		if _, ok := results[id]; !ok {
			t.Errorf("%s missing", id)
		}
	}
}

// The current complete pass moves the EV-08 history forward.
func TestEvaluatorSavesHistory(t *testing.T) {
	facts := &fakeFacts{
		currentIdentity: map[string][]fact.IdentitySnapshot{"001": {identityPass("cur", 1, true)}},
		identityRecords: map[string][]fact.IdentityRecord{"cur": {{AccountName: "ana", UID: 1500, Shell: "/bin/bash", PasswordState: "set"}}},
	}
	hist := &memHistory{}

	if _, err := begin(t, facts, hist).Agent(context.Background(), verdict.Agent{ID: "001", Name: "a"}, noParams{}); err != nil {
		t.Fatal(err)
	}
	if len(hist.saved) != 1 || hist.saved[0].AccountName != "ana" || hist.saved[0].AgentName != "a" {
		t.Errorf("saved: %+v", hist.saved)
	}
}

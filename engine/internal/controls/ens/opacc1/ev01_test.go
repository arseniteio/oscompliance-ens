package opacc1

import (
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// readSnapshot returns a snapshot that was read, announcing emitted records.
func readSnapshot(emitted int, dups ...fact.DuplicateUID) *fact.AccountInventorySnapshot {
	total := 20
	if dups == nil {
		dups = []fact.DuplicateUID{}
	}
	return &fact.AccountInventorySnapshot{
		Source: "passwd", SourcePath: "/etc/passwd", SourceStatus: fact.SourceRead, UIDMin: 1000,
		EntriesTotal: &total, RecordsEmitted: &emitted, DuplicateUIDs: dups,
	}
}

func notRead(status, why string) *fact.AccountInventorySnapshot {
	return &fact.AccountInventorySnapshot{
		Source: "passwd", SourcePath: "/etc/passwd", SourceStatus: status, SourceError: why, UIDMin: 1000,
	}
}

func records(n int) []fact.AccountRecord {
	out := make([]fact.AccountRecord, n)
	for i := range out {
		out[i] = fact.AccountRecord{AccountName: "user", UID: 1000 + i, GID: 1000 + i, Shell: "/bin/bash", LoginEnabled: true}
	}
	return out
}

func TestJudgeEV01(t *testing.T) {
	dup := fact.DuplicateUID{UID: 0, AccountNames: []string{"root", "toor"}}

	cases := []struct {
		name         string
		in           EV01Input
		status       verdict.Status
		cause        verdict.Cause
		reasonHasStr string // the reason must contain it; "" = no check
	}{
		{"no snapshot in the window", EV01Input{}, verdict.NotEvaluable, verdict.CauseCollection, ""},
		{"source unreadable", EV01Input{Snapshot: notRead(fact.SourceUnreadable, "permission denied")}, verdict.NotEvaluable, verdict.CauseCollection, "permission denied"},
		{"source implausible", EV01Input{Snapshot: notRead(fact.SourceImplausible, "no entry with UID 0")}, verdict.NotEvaluable, verdict.CauseCollection, "no entry with UID 0"},
		{"fewer records than announced", EV01Input{Snapshot: readSnapshot(3), Records: records(2)}, verdict.NotEvaluable, verdict.CauseCollection, ""},
		{"incomplete pass wins over duplicates", EV01Input{Snapshot: readSnapshot(3, dup), Records: records(1)}, verdict.NotEvaluable, verdict.CauseCollection, ""},
		{"read snapshot without counters", EV01Input{Snapshot: &fact.AccountInventorySnapshot{SourceStatus: fact.SourceRead}}, verdict.NotEvaluable, verdict.CauseEvidence, "records_emitted"},
		{"duplicate UIDs", EV01Input{Snapshot: readSnapshot(3, dup), Records: records(3)}, verdict.NonCompliant, "", "UID 0 (root, toor)"},
		{"clean inventory", EV01Input{Snapshot: readSnapshot(3), Records: records(3)}, verdict.Compliant, "", ""},
		{"no accounts above uid_min", EV01Input{Snapshot: readSnapshot(0)}, verdict.Compliant, "", ""},
		{"more records than announced (repeated delivery)", EV01Input{Snapshot: readSnapshot(2), Records: records(3)}, verdict.Compliant, "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV01(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			// Every verdict other than COMPLIANT must say why.
			if got.Status != verdict.Compliant && got.Reason == "" {
				t.Error("empty reason")
			}
			if c.reasonHasStr != "" && !strings.Contains(got.Reason, c.reasonHasStr) {
				t.Errorf("reason %q does not contain %q", got.Reason, c.reasonHasStr)
			}
		})
	}
}

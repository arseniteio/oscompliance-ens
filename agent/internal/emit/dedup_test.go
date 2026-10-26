package emit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

func pass(t *testing.T, runID string, at time.Time, records ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	e := New(&buf, "h", "1.0", runID)
	e.now = func() time.Time { return at }
	for _, r := range records {
		if err := e.Emit(fact.GroupRecord{Envelope: e.Envelope(fact.GroupRecordFact), GroupName: r, Members: []string{}}); err != nil {
			t.Fatal(err)
		}
	}
	n := len(records)
	if err := e.Emit(fact.GroupSnapshot{Envelope: e.Envelope(fact.GroupSnapshotFact), GroupPath: "/etc/group", GroupStatus: "read", RecordsEmitted: &n}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReduce(t *testing.T) {

	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	const run1, run2, run3 = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"

	// First pass: everything goes out.
	s := LoadState(path)
	out, commit, err := s.Reduce("groups", pass(t, run1, now, "root", "sudo"), now, false)
	if err != nil || strings.Count(string(out), "\n") != 3 {
		t.Fatalf("first pass: %v %q", err, out)
	}
	commit()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// An hour later, same groups: the snapshot alone, pointing to run1.
	s = LoadState(path)
	out, _, _ = s.Reduce("groups", pass(t, run2, now.Add(time.Hour), "root", "sudo"), now.Add(time.Hour), false)
	var snap map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &snap); err != nil || snap["records_run_id"] != run1 || snap["run_id"] != run2 || snap["fact"] != "group_snapshot" {
		t.Fatalf("unchanged pass: %v %s", err, out)
	}

	// A change: everything again.
	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(2*time.Hour), "root", "sudo", "ops"), now.Add(2*time.Hour), false)
	if strings.Count(string(out), "\n") != 4 {
		t.Errorf("changed pass: %q", out)
	}

	// Unchanged but a day later: everything again.
	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(FullEvery), "root", "sudo"), now.Add(FullEvery), false)
	if strings.Count(string(out), "\n") != 3 {
		t.Errorf("daily pass: %q", out)
	}

	// Forced full.
	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(time.Hour), "root", "sudo"), now.Add(time.Hour), true)
	if strings.Count(string(out), "\n") != 3 {
		t.Errorf("forced pass: %q", out)
	}

	// A damaged state file is an empty state.
	if s := LoadState(filepath.Join(t.TempDir(), "missing.json")); len(s.Collectors) != 0 {
		t.Error("missing state")
	}
}

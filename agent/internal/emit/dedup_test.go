package emit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
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

	s := LoadState(path)
	out, commit, err := s.Reduce("groups", pass(t, run1, now, "root", "sudo"), now, false, false)
	if err != nil || strings.Count(string(out), "\n") != 3 {
		t.Fatalf("first pass: %v %q", err, out)
	}
	commit()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	s = LoadState(path)
	out, _, _ = s.Reduce("groups", pass(t, run2, now.Add(time.Hour), "root", "sudo"), now.Add(time.Hour), false, false)
	var snap map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &snap); err != nil || snap["records_run_id"] != run1 || snap["run_id"] != run2 || snap["fact"] != "group_snapshot" {
		t.Fatalf("unchanged pass: %v %s", err, out)
	}

	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(2*time.Hour), "root", "sudo", "ops"), now.Add(2*time.Hour), false, false)
	if strings.Count(string(out), "\n") != 4 {
		t.Errorf("changed pass: %q", out)
	}

	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(FullEvery), "root", "sudo"), now.Add(FullEvery), false, false)
	if strings.Count(string(out), "\n") != 3 {
		t.Errorf("daily pass: %q", out)
	}

	out, _, _ = s.Reduce("groups", pass(t, run3, now.Add(time.Hour), "root", "sudo"), now.Add(time.Hour), true, false)
	if strings.Count(string(out), "\n") != 3 {
		t.Errorf("forced pass: %q", out)
	}

	if s := LoadState(filepath.Join(t.TempDir(), "missing.json")); len(s.Collectors) != 0 {
		t.Error("missing state")
	}
}

func TestReduceQuiet(t *testing.T) {

	s := LoadState(filepath.Join(t.TempDir(), "state.json"))
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	const run1, run2, run3 = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"

	out, commit, err := s.Reduce("groups", pass(t, run1, now, "root"), now, false, true)
	if err != nil || strings.Count(string(out), "\n") != 2 {
		t.Fatalf("first pass: %v %q", err, out)
	}
	commit()
	if got := s.InForce("groups"); got != "group_snapshot:"+run1 {
		t.Fatalf("in force: %q", got)
	}

	out, commit, _ = s.Reduce("groups", pass(t, run2, now.Add(time.Hour), "root"), now.Add(time.Hour), false, true)
	if len(out) != 0 {
		t.Fatalf("unchanged pass: %q", out)
	}
	commit()
	if got := s.InForce("groups"); got != "group_snapshot:"+run1 {
		t.Fatalf("in force after a quiet pass: %q", got)
	}

	var buf bytes.Buffer
	e := New(&buf, "h", "1.0", run3)
	n := 1
	if err := e.Emit(fact.GroupRecord{Envelope: e.Envelope(fact.GroupRecordFact), GroupName: "root", Members: []string{}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(fact.GroupSnapshot{Envelope: e.Envelope(fact.GroupSnapshotFact), GroupPath: "/etc/group", GroupStatus: "read", RecordsEmitted: &n, GroupError: "slow"}); err != nil {
		t.Fatal(err)
	}
	out, commit, _ = s.Reduce("groups", buf.Bytes(), now.Add(2*time.Hour), false, true)
	var snap map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &snap); err != nil || snap["records_run_id"] != run1 || snap["run_id"] != run3 {
		t.Fatalf("new snapshot: %v %s", err, out)
	}
	commit()
	if got := s.InForce("groups"); got != "group_snapshot:"+run3 {
		t.Fatalf("in force after a new snapshot: %q", got)
	}

	out, _, _ = s.Reduce("groups", pass(t, run2, now.Add(FullEvery), "root"), now.Add(FullEvery), false, true)
	if strings.Count(string(out), "\n") != 2 {
		t.Fatalf("full pass: %q", out)
	}
}

func TestReduceQuietSingleFact(t *testing.T) {

	s := LoadState(filepath.Join(t.TempDir(), "state.json"))
	now := time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC)
	line := func(run string) []byte {
		var buf bytes.Buffer
		e := New(&buf, "h", "1.0", run)
		e.now = func() time.Time { return now }
		if err := e.Emit(fact.UmaskSnapshot{Envelope: e.Envelope(fact.UmaskSnapshotFact), Sources: []fact.UmaskSource{}}); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	if out, _, _ := s.Reduce("probe", line("11111111-1111-4111-8111-111111111111"), now, false, false); len(out) == 0 {
		t.Fatal("loud collector sent nothing")
	}

	out, commit, _ := s.Reduce("umask", line("11111111-1111-4111-8111-111111111111"), now, false, true)
	commit()
	if strings.Count(string(out), "\n") != 1 {
		t.Fatalf("first pass: %q", out)
	}
	if out, _, _ := s.Reduce("umask", line("22222222-2222-4222-8222-222222222222"), now.Add(time.Hour), false, true); len(out) != 0 {
		t.Fatalf("unchanged pass: %q", out)
	}
}

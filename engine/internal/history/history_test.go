package history

import (
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

func record(name, state string) fact.IdentityRecord {
	return fact.IdentityRecord{AccountName: name, UID: 1500, Shell: "/bin/bash", PasswordState: state}
}

// lockedIsDisabled: "locked" disabled, "other" unknown, anything else enabled.
func lockedIsDisabled(r fact.IdentityRecord, _ time.Time) (bool, bool) {
	if r.PasswordState == fact.PasswordOther {
		return false, false
	}
	return r.PasswordState == fact.PasswordLocked, true
}

// apply runs Update and merges the changes, as the engine does with the index.
func apply(known map[string]Account, records []fact.IdentityRecord, at time.Time, run string) []Account {
	changed := Update(known, "001", "a", records, at, run, lockedIsDisabled)
	for _, c := range changed {
		known[c.AccountName] = c
	}
	return changed
}

func TestUpdateLifecycle(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2, t3, t4 := t1.AddDate(0, 0, 10), t1.AddDate(0, 0, 20), t1.AddDate(0, 0, 30)
	known := map[string]Account{}

	// First pass: ana enabled, old already disabled (no transition seen).
	if n := len(apply(known, []fact.IdentityRecord{record("ana", "set"), record("old", "locked")}, t1, "r1")); n != 2 {
		t.Fatalf("first pass: want 2 new accounts, got %d", n)
	}
	if known["old"].DisabledSince == nil || known["old"].DisabledObserved {
		t.Errorf("old: disabled at first sight must not count as observed: %+v", known["old"])
	}

	// Same pass again: nothing changes.
	if n := len(apply(known, []fact.IdentityRecord{record("ana", "set"), record("old", "locked")}, t1, "r1")); n != 0 {
		t.Errorf("same pass twice: want 0 changes, got %d", n)
	}

	// ana gets locked: transition observed.
	apply(known, []fact.IdentityRecord{record("ana", "locked"), record("old", "locked")}, t2, "r2")
	if a := known["ana"]; a.DisabledSince == nil || !a.DisabledSince.Equal(t2) || !a.DisabledObserved {
		t.Errorf("ana locked: %+v", a)
	}

	// Still locked later: DisabledSince keeps the first date.
	apply(known, []fact.IdentityRecord{record("ana", "locked"), record("old", "locked")}, t3, "r3")
	if a := known["ana"]; !a.DisabledSince.Equal(t2) || !a.LastSeen.Equal(t3) {
		t.Errorf("ana still locked: %+v", a)
	}

	// Both deleted.
	apply(known, nil, t4, "r4")
	for _, name := range []string{"ana", "old"} {
		if d := known[name].DeletedAt; d == nil || !d.Equal(t4) {
			t.Errorf("%s deleted: %+v", name, known[name])
		}
	}

	// Deleted stays deleted on the next pass: no new change.
	if n := len(apply(known, nil, t4.AddDate(0, 0, 1), "r5")); n != 0 {
		t.Errorf("already deleted: want 0 changes, got %d", n)
	}

	// Re-created: no longer deleted, enabled again.
	apply(known, []fact.IdentityRecord{record("ana", "set")}, t4.AddDate(0, 0, 2), "r6")
	if a := known["ana"]; a.DeletedAt != nil || a.DisabledSince != nil {
		t.Errorf("ana re-created: %+v", a)
	}
}

func TestUpdateUnknownState(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	known := map[string]Account{}

	apply(known, []fact.IdentityRecord{record("kim", "other")}, t1, "r1")
	if a := known["kim"]; !a.StateUnknown || a.DisabledSince != nil {
		t.Errorf("unknown at first sight: %+v", a)
	}

	// Becomes disabled after an unknown state: not an observed change.
	apply(known, []fact.IdentityRecord{record("kim", "locked")}, t1.AddDate(0, 0, 1), "r2")
	if a := known["kim"]; a.StateUnknown || a.DisabledSince == nil || a.DisabledObserved {
		t.Errorf("disabled after unknown: %+v", a)
	}

	// Unknown again: the recorded disabling stays.
	apply(known, []fact.IdentityRecord{record("kim", "other")}, t1.AddDate(0, 0, 2), "r3")
	if a := known["kim"]; !a.StateUnknown || a.DisabledSince == nil {
		t.Errorf("unknown after disabled: %+v", a)
	}
}

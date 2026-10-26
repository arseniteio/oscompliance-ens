package opacc1

import (
	"reflect"
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func identity(name string, uid int, state string) fact.IdentityRecord {
	return fact.IdentityRecord{
		Envelope:    fact.Envelope{RunID: "run-" + name, TS: "2026-10-21T14:00:00Z"},
		AccountName: name, UID: uid, GID: uid, Shell: "/bin/bash", PasswordState: state,
	}
}

func TestDiffIdentities(t *testing.T) {

	root := identity("root", 0, "locked")
	alice := identity("alice", 1000, "set")
	bob := identity("bob", 1001, "set")

	aliceLocked := alice
	aliceLocked.PasswordState = "locked"

	bobOtherPass := bob
	bobOtherPass.RunID, bobOtherPass.TS, bobOtherPass.AgentVersion = "other", "2026-10-22T00:00:00Z", "2"

	one, otherOne, two := 1, 1, 2
	keyed := identity("kim", 1004, "locked")
	keyed.AuthorizedKeys = &one
	keyedSame := keyed
	keyedSame.AuthorizedKeys = &otherOne
	keyedMore := keyed
	keyedMore.AuthorizedKeys = &two
	keyedUnknown := keyed
	keyedUnknown.AuthorizedKeys = nil

	carol := identity("carol", 1002, "set")
	dave := identity("dave", 1003, "set")
	daveExpires := dave
	daveExpires.AccountExpires = "2027-01-01"

	cases := []struct {
		name     string
		previous []fact.IdentityRecord
		current  []fact.IdentityRecord
		want     IdentityChanges
	}{
		{"same accounts, envelope differs", []fact.IdentityRecord{root, bob}, []fact.IdentityRecord{root, bobOtherPass}, IdentityChanges{}},
		{"created", []fact.IdentityRecord{root}, []fact.IdentityRecord{root, carol, alice}, IdentityChanges{Created: []string{"alice", "carol"}}},
		{"deleted", []fact.IdentityRecord{root, bob, alice}, []fact.IdentityRecord{root}, IdentityChanges{Deleted: []string{"alice", "bob"}}},
		{"modified password state", []fact.IdentityRecord{alice}, []fact.IdentityRecord{aliceLocked}, IdentityChanges{Modified: []string{"alice"}}},
		{"modified expiry", []fact.IdentityRecord{dave}, []fact.IdentityRecord{daveExpires}, IdentityChanges{Modified: []string{"dave"}}},
		{"all three", []fact.IdentityRecord{root, alice, bob}, []fact.IdentityRecord{root, aliceLocked, carol}, IdentityChanges{Created: []string{"carol"}, Deleted: []string{"bob"}, Modified: []string{"alice"}}},
		{"same key count in another pass", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedSame}, IdentityChanges{}},
		{"key added", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedMore}, IdentityChanges{Modified: []string{"kim"}}},
		{"keys became unknown", []fact.IdentityRecord{keyed}, []fact.IdentityRecord{keyedUnknown}, IdentityChanges{Modified: []string{"kim"}}},
		{"name twice: first wins", []fact.IdentityRecord{alice}, []fact.IdentityRecord{alice, aliceLocked}, IdentityChanges{}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DiffIdentities(c.previous, c.current)

			if !sameList(got.Created, c.want.Created) || !sameList(got.Deleted, c.want.Deleted) || !sameList(got.Modified, c.want.Modified) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func sameList(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return reflect.DeepEqual(a, b)
}

func identitySnapshot(runID string, emitted int) *fact.IdentitySnapshot {
	return &fact.IdentitySnapshot{
		Envelope:   fact.Envelope{RunID: runID},
		PasswdPath: "/etc/passwd", PasswdStatus: fact.SourceRead,
		ShadowPath: "/etc/shadow", ShadowStatus: fact.SourceRead,
		RecordsEmitted: &emitted,
	}
}

func TestJudgeEV02(t *testing.T) {

	root := identity("root", 0, "locked")
	alice := identity("alice", 1000, "set")
	bob := identity("bob", 1001, "set")

	shadowDenied := identitySnapshot("cur", 0)
	shadowDenied.ShadowStatus, shadowDenied.ShadowError, shadowDenied.RecordsEmitted = fact.SourceUnreadable, "permission denied", nil

	passwdBad := identitySnapshot("cur", 0)
	passwdBad.PasswdStatus, passwdBad.PasswdError = fact.SourceImplausible, "no entry with UID 0"
	passwdBad.ShadowStatus, passwdBad.ShadowError, passwdBad.RecordsEmitted = fact.SourceUnreadable, "not read", nil

	noCounter := identitySnapshot("cur", 0)
	noCounter.RecordsEmitted = nil

	cases := []struct {
		name    string
		in      EV02Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"no snapshot", EV02Input{}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"shadow unreadable", EV02Input{Current: shadowDenied}, verdict.NotEvaluable, verdict.CauseCollection, []string{"permission denied"}},
		{"passwd implausible", EV02Input{Current: passwdBad}, verdict.NotEvaluable, verdict.CauseCollection, []string{"no entry with UID 0"}},
		{"read without counter", EV02Input{Current: noCounter}, verdict.NotEvaluable, verdict.CauseEvidence, []string{"records_emitted"}},
		{"incomplete pass", EV02Input{Current: identitySnapshot("cur", 3), Records: []fact.IdentityRecord{root}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"baseline", EV02Input{Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, alice}}, verdict.Compliant, "", []string{"baseline", "2 accounts"}},
		{"no changes", EV02Input{
			Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, alice},
			Previous: identitySnapshot("prev", 2), PreviousRecords: []fact.IdentityRecord{root, alice},
		}, verdict.Compliant, "", []string{"no changes since prev"}},
		{"changes", EV02Input{
			Current: identitySnapshot("cur", 2), Records: []fact.IdentityRecord{root, bob},
			Previous: identitySnapshot("prev", 2), PreviousRecords: []fact.IdentityRecord{root, alice},
		}, verdict.Compliant, "", []string{"since prev", "created: bob", "deleted: alice"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV02(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			if got.Status != verdict.Compliant && got.Reason == "" {
				t.Error("empty reason")
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
			if strings.Contains(got.Reason, "modified") && c.name == "changes" {
				t.Errorf("reason lists an empty list: %q", got.Reason)
			}
		})
	}
}

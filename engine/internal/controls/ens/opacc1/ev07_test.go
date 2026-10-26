package opacc1

import (
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func TestJudgeEV07(t *testing.T) {
	root := account("root", 0, "locked", 0)
	jperez := account("jperez", 1001, "locked", 1)
	mgarcia := account("mgarcia", 1002, "set", 0)
	old := account("old", 1003, "locked", 0)
	unknown := account("kim", 1004, "locked", -1)

	nologin := account("svc", 1005, "set", 0)
	nologin.Shell = "/usr/sbin/nologin"

	incomplete := inventory(jperez)
	incomplete.Current = identitySnapshot("cur", 3)

	cases := []struct {
		name    string
		in      EV07Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-07 not set", EV07Input{AuthorizedProblem: "not set", Inventory: inventory(root)}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-07: not set"}},
		{"no inventory", EV07Input{Authorized: []string{"jperez"}, Inventory: Inventory{UIDMin: DefaultUIDMin}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"incomplete inventory", EV07Input{Authorized: []string{"jperez"}, Inventory: incomplete}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"unauthorized active account", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(root, jperez, mgarcia)}, verdict.NonCompliant, "", []string{"not in P-07: mgarcia"}},
		{"key login counts as active", EV07Input{Authorized: []string{"mgarcia"}, Inventory: inventory(jperez, mgarcia)}, verdict.NonCompliant, "", []string{"jperez"}},
		{"case matters", EV07Input{Authorized: []string{"JPerez"}, Inventory: inventory(jperez)}, verdict.NonCompliant, "", []string{"jperez"}},
		{"disabled accounts do not count", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(root, jperez, old, nologin)}, verdict.Compliant, "", []string{"1 active accounts"}},
		{"system accounts do not count", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(account("daemon", 1, "set", 0), jperez)}, verdict.Compliant, "", nil},
		{"unknown and not listed", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(jperez, unknown)}, verdict.NotEvaluable, verdict.CauseEvidence, []string{"kim"}},
		{"unknown but listed", EV07Input{Authorized: []string{"jperez", "kim"}, Inventory: inventory(jperez, unknown)}, verdict.Compliant, "", nil},
		{"all authorized", EV07Input{Authorized: []string{"jperez", "mgarcia"}, Inventory: inventory(jperez, mgarcia)}, verdict.Compliant, "", []string{"2 active accounts, all in P-07"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV07(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

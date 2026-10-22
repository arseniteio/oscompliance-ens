package opacc1

import (
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

func account(name string, login bool) fact.AccountRecord {
	return fact.AccountRecord{AccountName: name, UID: 1000, GID: 1000, Shell: "/bin/bash", LoginEnabled: login}
}

func TestJudgeEV07(t *testing.T) {
	inventory := func(records ...fact.AccountRecord) EV01Input {
		return EV01Input{Snapshot: readSnapshot(len(records)), Records: records}
	}

	cases := []struct {
		name    string
		in      EV07Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-07 not set", EV07Input{AuthorizedProblem: "not set", Inventory: inventory()}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-07: not set"}},
		{"no inventory", EV07Input{Authorized: []string{"jperez"}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"incomplete inventory", EV07Input{Authorized: []string{"jperez"}, Inventory: EV01Input{Snapshot: readSnapshot(3), Records: records(1)}}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"unauthorized active account", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(account("jperez", true), account("mgarcia", true))}, verdict.NonCompliant, "", []string{"not in P-07: mgarcia"}},
		{"case matters", EV07Input{Authorized: []string{"JPerez"}, Inventory: inventory(account("jperez", true))}, verdict.NonCompliant, "", []string{"jperez"}},
		{"accounts without login do not count", EV07Input{Authorized: []string{"jperez"}, Inventory: inventory(account("jperez", true), account("backup-svc", false))}, verdict.Compliant, "", []string{"1 active accounts"}},
		{"all authorized", EV07Input{Authorized: []string{"jperez", "mgarcia"}, Inventory: inventory(account("jperez", true), account("mgarcia", true))}, verdict.Compliant, "", []string{"2 active accounts, all in P-07"}},
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

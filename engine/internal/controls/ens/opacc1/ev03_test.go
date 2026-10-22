package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

func login(account string) source.Login {
	return source.Login{Time: time.Date(2026, 10, 22, 11, 40, 0, 0, time.UTC), Account: account, SourceIP: "10.0.0.9"}
}

func TestJudgeEV03(t *testing.T) {
	t.Skip("remove when JudgeEV03 is written")

	generic := []string{"admin", "guest", "test"}

	cases := []struct {
		name    string
		in      EV03Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string // each must appear in the reason
	}{
		{"P-04 not set", EV03Input{GenericProblem: "not set", AuthSeen: true}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-04", "not set"}},
		{"P-04 problem wins over a silent source", EV03Input{GenericProblem: "not set"}, verdict.NotEvaluable, verdict.CauseConfiguration, nil},
		{"no authentication events", EV03Input{Generic: generic}, verdict.NotEvaluable, verdict.CauseCollection, []string{"no authentication events"}},
		{"generic account logged in", EV03Input{Generic: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("admin")}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"case is ignored", EV03Input{Generic: generic, AuthSeen: true, Logins: []source.Login{login("Admin")}}, verdict.NonCompliant, "", []string{"(1)"}},
		{"counted and sorted", EV03Input{Generic: generic, AuthSeen: true, Logins: []source.Login{login("test"), login("admin"), login("test")}}, verdict.NonCompliant, "", []string{"admin (1), test (2)"}},
		{"only named accounts", EV03Input{Generic: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("mgarcia")}}, verdict.Compliant, "", []string{"2 sshd logins"}},
		{"source alive, no logins", EV03Input{Generic: generic, AuthSeen: true}, verdict.Compliant, "", []string{"0 sshd logins"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV03(c.in)

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
		})
	}
}

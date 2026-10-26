package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func login(account string) source.Login {
	return source.Login{Time: time.Date(2026, 10, 22, 11, 40, 0, 0, time.UTC), Account: account, SourceIP: "10.0.0.9", Method: source.MethodSSHD}
}

func TestJudgeEV03(t *testing.T) {
	generic := params.ListMatcher("admin", "guest", "test")

	pattern, err := params.PatternMatcher("(adm|tmp)[0-9]*")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		in      LoginInput
		status  verdict.Status
		cause   verdict.Cause
		reasons []string // each must appear in the reason
	}{
		{"P-04 not set", LoginInput{ForbiddenProblem: "not set", AuthSeen: true}, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-04", "not set"}},
		{"P-04 problem wins over a silent source", LoginInput{ForbiddenProblem: "not set"}, verdict.NotEvaluable, verdict.CauseConfiguration, nil},
		{"no authentication events", LoginInput{Forbidden: generic}, verdict.NotEvaluable, verdict.CauseCollection, []string{"no authentication events"}},
		{"generic account logged in", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("admin")}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"case is ignored", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("Admin")}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"one account whatever its case", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("Admin"), login("admin")}}, verdict.NonCompliant, "", []string{"admin (2)"}},
		{"counted and sorted", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("test"), login("admin"), login("test")}}, verdict.NonCompliant, "", []string{"admin (1), test (2)"}},
		{"only named accounts", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), login("mgarcia")}}, verdict.Compliant, "", []string{"2 logins in the window (sshd 2)"}},
		{"su to a generic account counts", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{{Account: "admin", Method: source.MethodSU}}}, verdict.NonCompliant, "", []string{"admin (1)"}},
		{"methods counted", LoginInput{Forbidden: generic, AuthSeen: true, Logins: []source.Login{login("jperez"), {Account: "ana", Method: source.MethodConsole}, {Account: "ana", Method: source.MethodSU}}}, verdict.Compliant, "", []string{"3 logins in the window (console 1, sshd 1, su 1)"}},
		{"pattern: whole name", LoginInput{Forbidden: pattern, AuthSeen: true, Logins: []source.Login{login("tmp7"), login("admin"), login("xadm")}}, verdict.NonCompliant, "", []string{"generic accounts authenticated: tmp7 (1)"}},
		{"source alive, no logins", LoginInput{Forbidden: generic, AuthSeen: true}, verdict.Compliant, "", []string{"0 logins in the window, none"}},
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

// EV-05 is the same judgement against P-03: only the list and the words change.
func TestJudgeEV05(t *testing.T) {
	service := params.ListMatcher("daemon", "www-data", "sshd")

	got := JudgeEV05(LoginInput{Forbidden: service, AuthSeen: true, Logins: []source.Login{login("jperez"), login("www-data")}})
	if got.Status != verdict.NonCompliant || !strings.Contains(got.Reason, "service accounts authenticated: www-data (1)") {
		t.Errorf("service login: %+v", got)
	}

	got = JudgeEV05(LoginInput{Forbidden: service, AuthSeen: true, Logins: []source.Login{login("jperez")}})
	if got.Status != verdict.Compliant || !strings.Contains(got.Reason, "P-03") {
		t.Errorf("named login: %+v", got)
	}

	got = JudgeEV05(LoginInput{ForbiddenProblem: "not set", AuthSeen: true})
	if got.Status != verdict.NotEvaluable || got.Cause != verdict.CauseConfiguration || !strings.Contains(got.Reason, "P-03: not set") {
		t.Errorf("P-03 not set: %+v", got)
	}
}

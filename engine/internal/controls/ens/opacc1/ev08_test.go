package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

func deletedAccount(name string, disabled, deleted string, observed bool, expires string) history.Account {
	a := history.Account{AccountName: name, UID: 1500, AccountExpires: expires, DisabledObserved: observed}
	if disabled != "" {
		d := day(disabled)
		a.DisabledSince = &d
	}
	del := day(deleted)
	a.DeletedAt = &del
	return a
}

func TestJudgeEV08(t *testing.T) {
	base := func(deleted ...history.Account) EV08Input {
		return EV08Input{Deleted: deleted, RetentionDays: 30, Declared: map[string]time.Time{}, UIDMin: DefaultUIDMin}
	}

	badConfig := base()
	badConfig.ConfigProblem = "P-06: not set"

	noIdentity := base()
	noIdentity.IdentityProblem = "no complete identity pass"

	declared := base(deletedAccount("ana", "2026-10-01", "2026-10-20", false, ""))
	declared.Declared["ana"] = day("2026-09-01")

	unknownState := deletedAccount("lee", "", "2026-10-10", false, "")
	unknownState.StateUnknown = true

	system := deletedAccount("svc", "2026-10-01", "2026-10-02", true, "")
	system.UID = 500

	cases := []struct {
		name    string
		in      EV08Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"configuration problem", badConfig, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-06"}},
		{"no identity pass", noIdentity, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"nothing deleted", base(), verdict.Compliant, "", []string{"no account deleted"}},
		{"observed disabling, deleted too early", base(deletedAccount("ana", "2026-10-01", "2026-10-11", true, "")), verdict.NonCompliant, "", []string{"ana (10 days)", "30 days (P-06)"}},
		{"observed disabling, kept long enough", base(deletedAccount("ana", "2026-08-01", "2026-10-11", true, "")), verdict.Compliant, "", []string{"1 accounts deleted"}},
		{"P-09 date wins", declared, verdict.Compliant, "", nil},
		{"expiry date used", base(deletedAccount("eva", "2026-10-05", "2026-10-10", false, "2026-10-01")), verdict.NonCompliant, "", []string{"eva (9 days)"}},
		{"start unknown", base(deletedAccount("old", "2026-10-05", "2026-10-10", false, "")), verdict.NotEvaluable, verdict.CauseEvidence, []string{"old"}},
		{"last state unknown", base(unknownState), verdict.NotEvaluable, verdict.CauseEvidence, []string{"lee"}},
		{"deleted while enabled", base(deletedAccount("bob", "", "2026-10-10", false, "")), verdict.NonCompliant, "", []string{"bob (deleted while enabled)"}},
		{"too early wins over unknown", base(deletedAccount("bob", "", "2026-10-10", false, ""), deletedAccount("old", "2026-10-05", "2026-10-10", false, "")), verdict.NonCompliant, "", []string{"bob"}},
		{"system account ignored", base(system), verdict.Compliant, "", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV08(c.in)

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

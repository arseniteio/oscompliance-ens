package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

func person(name string, state, expires string) fact.IdentityRecord {
	return fact.IdentityRecord{AccountName: name, UID: 1500, GID: 1500, Shell: "/bin/bash", PasswordState: state, AccountExpires: expires}
}

func day(s string) time.Time {
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestJudgeEV04(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

	base := func(accounts ...fact.IdentityRecord) EV04Input {
		return EV04Input{Accounts: accounts, Declared: map[string]time.Time{}, DeadlineDays: 1, UIDMin: DefaultUIDMin, Now: now}
	}
	declare := func(in EV04Input, name, date string) EV04Input {
		in.Declared[name] = day(date)
		in.DeclaredSet = true
		return in
	}

	system := person("svc", "set", "")
	system.UID = 500

	nologin := person("ana", "set", "")
	nologin.Shell = "/usr/sbin/nologin"

	badConfig := base()
	badConfig.ConfigProblem = "P-05: not set"

	noIdentity := base()
	noIdentity.Accounts, noIdentity.AccountsProblem = nil, "no complete identity pass"

	cases := []struct {
		name    string
		in      EV04Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"configuration problem", badConfig, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-05"}},
		{"no identity table", noIdentity, verdict.NotEvaluable, verdict.CauseCollection, []string{"no complete identity pass"}},
		{"declared and still enabled past the deadline", declare(base(person("antonio", "set", "")), "antonio", "2026-10-01"), verdict.NonCompliant, "", []string{"antonio (21 days)", "1 days (P-05)"}},
		{"declared, within the deadline", declare(base(person("antonio", "set", "")), "antonio", "2026-10-21"), verdict.Compliant, "", []string{"1 accounts"}},
		{"declared and locked", declare(base(person("antonio", "locked", "")), "antonio", "2026-10-01"), verdict.Compliant, "", nil},
		{"declared and no-login shell", declare(base(nologin), "ana", "2026-10-01"), verdict.Compliant, "", nil},
		{"declared, account already deleted", declare(base(person("jperez", "set", "")), "antonio", "2026-07-31"), verdict.Compliant, "", []string{"0 accounts"}},
		{"expiry in the past disables", base(person("eva", "set", "2026-09-01")), verdict.Compliant, "", []string{"1 accounts"}},
		{"system account ignored", declare(base(system), "svc", "2026-01-01"), verdict.Compliant, "", []string{"0 accounts"}},
		{"no dates at all", base(person("jperez", "set", "")), verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-09 is empty"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV04(c.in)

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

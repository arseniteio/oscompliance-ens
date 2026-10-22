package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

func person(name string, state, expires string) fact.IdentityRecord {
	none := 0
	return fact.IdentityRecord{AccountName: name, UID: 1500, GID: 1500, Shell: "/bin/bash", PasswordState: state, AccountExpires: expires, AuthorizedKeys: &none}
}

func withKeys(r fact.IdentityRecord, n int) fact.IdentityRecord {
	r.AuthorizedKeys = &n
	return r
}

func keysUnknown(r fact.IdentityRecord) fact.IdentityRecord {
	r.AuthorizedKeys = nil
	return r
}

func TestIsDisabled(t *testing.T) {
	today := day("2026-10-22")

	nologin := person("a", "set", "")
	nologin.Shell = "/usr/sbin/nologin"

	cases := []struct {
		name            string
		record          fact.IdentityRecord
		disabled, known bool
	}{
		{"no-login shell", nologin, true, true},
		{"expired", person("a", "set", "2026-10-01"), true, true},
		{"expires later", person("a", "set", "2027-01-01"), false, true},
		{"usable password", person("a", "set", ""), false, true},
		{"empty password logs in", person("a", "empty", ""), false, true},
		{"locked, no keys", person("a", "locked", ""), true, true},
		{"locked, with a key: still logs in", withKeys(person("a", "locked", ""), 1), false, true},
		{"no shadow entry, no keys", person("a", "missing", ""), true, true},
		{"locked, keys unknown", keysUnknown(person("a", "locked", "")), false, false},
		{"usable password, keys unknown: keys do not matter", keysUnknown(person("a", "set", "")), false, true},
	}

	for _, c := range cases {
		if d, k := IsDisabled(c.record, today); d != c.disabled || k != c.known {
			t.Errorf("%s: got disabled=%v known=%v, want %v %v", c.name, d, k, c.disabled, c.known)
		}
	}
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
		{"declared and locked, no keys", declare(base(person("antonio", "locked", "")), "antonio", "2026-10-01"), verdict.Compliant, "", nil},
		{"declared, locked but with a key", declare(base(withKeys(person("antonio", "locked", ""), 1)), "antonio", "2026-10-01"), verdict.NonCompliant, "", []string{"antonio (21 days)"}},
		{"declared, locked, keys unknown", declare(base(keysUnknown(person("antonio", "locked", ""))), "antonio", "2026-10-01"), verdict.NotEvaluable, verdict.CauseEvidence, []string{"SSH keys unknown: antonio"}},
		{"keys unknown but within the deadline", declare(base(keysUnknown(person("antonio", "locked", ""))), "antonio", "2026-10-21"), verdict.Compliant, "", nil},
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

package opacc1

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var evalDay = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

func account(name string, uid int, state string, keys int) fact.IdentityRecord {
	r := fact.IdentityRecord{AccountName: name, UID: uid, GID: uid, Shell: "/bin/bash", PasswordState: state}
	if keys >= 0 {
		r.AuthorizedKeys = &keys
	}
	return r
}

func inventory(records ...fact.IdentityRecord) Inventory {
	return Inventory{Current: identitySnapshot("cur", len(records)), Records: records, UIDMin: DefaultUIDMin, Today: evalDay}
}

func TestJudgeEV01(t *testing.T) {
	root := account("root", 0, "locked", 0)

	badP10 := inventory(root)
	badP10.UIDMinProblem = catalog.Says("param.invalid", "param", "P-10", "error", `"many" is not a number`)

	incomplete := inventory(root)
	incomplete.Current = identitySnapshot("cur", 3)

	shadowDenied := inventory()
	shadowDenied.Current.ShadowStatus, shadowDenied.Current.ShadowError, shadowDenied.Current.RecordsEmitted = fact.SourceUnreadable, "permission denied", nil

	cases := []struct {
		name    string
		in      Inventory
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-10 unusable", badP10, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-10"}},
		{"no identity pass", Inventory{UIDMin: DefaultUIDMin}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"shadow unreadable", shadowDenied, verdict.NotEvaluable, verdict.CauseCollection, []string{"permission denied"}},
		{"incomplete pass", incomplete, verdict.NotEvaluable, verdict.CauseCollection, []string{"1 of 3"}},
		{"duplicate UIDs, system ones included", inventory(root, account("toor", 0, "locked", 0), account("ana", 1001, "set", 0), account("bob", 1001, "set", 0)), verdict.NonCompliant, "", []string{"UID 0 (root, toor); UID 1001 (ana, bob)"}},
		{"unique UIDs", inventory(root, account("daemon", 1, "locked", 0), account("ana", 1001, "set", 0)), verdict.Compliant, "", []string{"3 accounts, 1 with UID >= 1000"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV01(c.in)

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

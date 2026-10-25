package opacc6

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV10Input is what EV-10 (suspension after a period without use) needs.
type EV10Input struct {
	Accounts Accounts
	Today    time.Time
	// LastAlert is, per account, the newest login Wazuh saw in the lookback:
	// it covers logins without a terminal, which wtmp does not record.
	LastAlert map[string]time.Time

	// MaxIdle is P-09 in days; MaxIdleProblem says why it cannot be used.
	MaxIdle        int
	MaxIdleProblem string
}

// JudgeEV10 judges EV-10 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. Identity pass unusable: NOT_EVALUABLE, COLLECTION. P-09 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. Each account that can still log in, at any UID: its last use is the
//     newest of its last login (wtmp, lastlog) and its newest login alert;
//     never used, the age of its newest credential counts instead.
//  3. Unused for longer than P-09 and still enabled: NON_COMPLIANT. Linux
//     suspends nothing by itself.
//  4. An account with no use and no credential date: NOT_EVALUABLE,
//     EVIDENCE. Otherwise COMPLIANT.
func JudgeEV10(in EV10Input) verdict.Judgement {

	// 1. Facts and parameter.
	if gap, found := in.Accounts.Gap(); found {
		return gap
	}
	if in.MaxIdleProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-09: "+in.MaxIdleProblem)
	}

	var idle, unknown []string
	examined := 0

	for _, a := range in.Accounts.Records {

		disabled, known := opacc1.IsDisabled(a, in.Today)
		if !known {
			unknown = append(unknown, a.AccountName+": cannot tell whether it can log in")
			continue
		}
		if disabled {
			continue
		}
		examined++

		// 2. Last use, or the credential when there was none.
		last, since := lastUse(a.LastLogin, in.LastAlert[a.AccountName]), "last used"

		if last.IsZero() {
			last, since = newestDate(a.PasswordChanged, a.AuthorizedKeysChanged), "never used, credential set"
		}

		if last.IsZero() {
			unknown = append(unknown, a.AccountName+": never used and no credential date")
			continue
		}

		// 3. Enabled and idle.
		if d := days(in.Today.Sub(last)); d > in.MaxIdle {
			idle = append(idle, fmt.Sprintf("%s (%s %d days ago)", a.AccountName, since, d))
		}
	}

	if len(idle) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("enabled and unused for more than %d days: %s", in.MaxIdle, strings.Join(idle, ", "))}
	}

	// 4. What could not be dated.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d accounts that can log in, all used within %d days", examined, in.MaxIdle)}
}

func lastUse(lastLogin string, alert time.Time) time.Time {

	last := alert

	if t, err := time.Parse(time.RFC3339, lastLogin); err == nil && t.After(last) {
		last = t
	}

	return last
}

// newestDate is the newest of a YYYY-MM-DD date and an RFC 3339 time.
func newestDate(date, stamp string) time.Time {

	var newest time.Time

	if t, err := time.Parse("2006-01-02", date); err == nil {
		newest = t
	}
	if t, err := time.Parse(time.RFC3339, stamp); err == nil && t.After(newest) {
		newest = t
	}

	return newest
}

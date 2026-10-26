package opacc6

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV10Input struct {
	Accounts Accounts
	Today    time.Time

	LastAlert map[string]time.Time

	MaxIdle        int
	MaxIdleProblem string
}

func JudgeEV10(in EV10Input) verdict.Judgement {

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

		last, since := lastUse(a.LastLogin, in.LastAlert[a.AccountName]), "last used"

		if last.IsZero() {
			last, since = newestDate(a.PasswordChanged, a.AuthorizedKeysChanged), "never used, credential set"
		}

		if last.IsZero() {
			unknown = append(unknown, a.AccountName+": never used and no credential date")
			continue
		}

		if d := days(in.Today.Sub(last)); d > in.MaxIdle {
			idle = append(idle, fmt.Sprintf("%s (%s %d days ago)", a.AccountName, since, d))
		}
	}

	if len(idle) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("enabled and unused for more than %d days: %s", in.MaxIdle, strings.Join(idle, ", "))}
	}

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

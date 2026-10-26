package opacc6

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

const attemptInterval = 15 * time.Minute

type EV04Input struct {
	Failures []source.Failure
	Lockouts []source.Lockout
	Log      passes.AuthLog

	MaxAttempts        int
	MaxAttemptsProblem string
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+in.MaxAttemptsProblem)
	}

	byAccount := map[string][]time.Time{}
	for _, f := range in.Failures {
		byAccount[f.Account] = append(byAccount[f.Account], f.Time)
	}

	locked := map[string]bool{}
	for _, l := range in.Lockouts {
		locked[l.Account] = true
	}

	var offenders []string
	worst := 0

	for account, times := range byAccount {

		n := maxWithin(times, attemptInterval)
		worst = max(worst, n)

		if n > in.MaxAttempts && !locked[account] {
			offenders = append(offenders, fmt.Sprintf("%s (%d failures within %s)", account, n, attemptInterval))
		}
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("more than %d failed attempts without a lockout: %s", in.MaxAttempts, strings.Join(offenders, ", "))}
	}

	if len(in.Failures) == 0 {
		if !in.Log.Reaches {
			return passes.NotEvaluable(verdict.CauseCollection, "failed attempts cannot be seen: "+in.Log.Detail)
		}
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no failed attempt in the window"}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d failed attempts on %d accounts, at most %d within %s or stopped by a lockout", len(in.Failures), len(byAccount), worst, attemptInterval),
	}
}

func maxWithin(times []time.Time, span time.Duration) int {

	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	best, start := 0, 0

	for end := range sorted {
		for sorted[end].Sub(sorted[start]) > span {
			start++
		}
		best = max(best, end-start+1)
	}

	return best
}

package opacc6

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_05_a", "a", in.MaxAttemptsProblem))
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
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.more_than_a_failed_attempts_without_a_lo", "a", in.MaxAttempts, "b", strings.Join(offenders, ", ")))
	}

	if len(in.Failures) == 0 {
		if !in.Log.Reaches {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.failed_attempts_cannot_be_seen_a", "a", in.Log.Detail))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_failed_attempt_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_failed_attempts_on_b_accounts_at_most", "a", len(in.Failures), "b", len(byAccount), "c", worst, "d", attemptInterval))
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

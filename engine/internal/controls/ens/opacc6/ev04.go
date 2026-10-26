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

// attemptInterval is the span in which failed attempts are counted
// together: pam_faillock's default fail_interval. A fixed span, so that a
// short configured interval cannot hide a slow attack.
const attemptInterval = 15 * time.Minute

// EV04Input is what EV-04 (failed attempts not stopped by a lockout) needs.
type EV04Input struct {
	// Failures and Lockouts in the window, as Wazuh decoded them.
	Failures []source.Failure
	Lockouts []source.Lockout
	Log      passes.AuthLog

	// MaxAttempts is P-05; MaxAttemptsProblem says why it cannot be used.
	MaxAttempts        int
	MaxAttemptsProblem string
}

// JudgeEV04 judges EV-04 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. P-05 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Per existing account, the most failed attempts within any 15 minutes,
//     from every origin together (v1 counted per origin and per hour, which
//     a spread or slow attack escaped). Names that do not exist accuse
//     nobody: Wazuh marks them invalid_login and they are left out.
//  3. More than P-05 and no lockout of the account in the window:
//     NON_COMPLIANT.
//  4. No failure while the authentication log is not known to reach Wazuh:
//     NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
func JudgeEV04(in EV04Input) verdict.Judgement {

	// 1. Parameter.
	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+in.MaxAttemptsProblem)
	}

	// 2. Failures per account.
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

		// 3. Too many and nothing stopped them.
		if n > in.MaxAttempts && !locked[account] {
			offenders = append(offenders, fmt.Sprintf("%s (%d failures within %s)", account, n, attemptInterval))
		}
	}

	if len(offenders) > 0 {
		sort.Strings(offenders)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("more than %d failed attempts without a lockout: %s", in.MaxAttempts, strings.Join(offenders, ", "))}
	}

	// 4. Silence.
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

// maxWithin is the largest number of times within any span.
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

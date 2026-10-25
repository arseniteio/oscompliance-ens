package opacc5

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// originSpan is the span in which failures from one origin are counted.
const originSpan = 15 * time.Minute

// EV03Input is what EV-03 (failures by origin) needs.
type EV03Input struct {
	Services []Service
	// Bursts per origin in the window (an upper bound per span), and the
	// exact failures of the origins whose bound is above P-03.
	Bursts   []source.Burst
	Failures []source.ServiceEvent
	// Reaching: the services whose log is known to reach Wazuh.
	Reaching map[string]bool

	MaxAttempts        int
	MaxAttemptsProblem string
}

// JudgeEV03 judges EV-03 as described in catalog/docs/contracts/op.acc.5.md:
//
//  1. P-03 unusable or no service: NOT_EVALUABLE, CONFIGURATION.
//  2. Per service and origin, the most failures within any 15 minutes
//     (v1 counted per hourly run, which a slow attack escaped). More than
//     P-03: NON_COMPLIANT: one origin tries many times and nothing stops it.
//  3. No failure from a service whose log is not known to reach Wazuh:
//     NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
func JudgeEV03(in EV03Input) verdict.Judgement {

	// 1. Parameter and subject.
	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-03: "+in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	// 2. Exact counts where the bound is too high.
	times := map[string][]time.Time{}
	for _, f := range in.Failures {
		key := f.Service + " " + origin(f.Origen)
		times[key] = append(times[key], f.Time)
	}

	var failing []string
	failed := map[string]int{}

	for _, b := range in.Bursts {

		failed[b.Service] += b.Total
		if b.AtMost <= in.MaxAttempts {
			continue
		}

		key := b.Service + " " + origin(b.Key)
		if n := maxWithin(times[key], originSpan); n > in.MaxAttempts {
			failing = append(failing, fmt.Sprintf("%s: %d failures within %s", key, n, originSpan))
		}
	}

	if len(failing) > 0 {
		sort.Strings(failing)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("origins with more than %d failures: %s", in.MaxAttempts, strings.Join(failing, "; "))}
	}

	// 3. Silence.
	var blind []string
	for _, s := range in.Services {
		if failed[s.Name] == 0 && !in.Reaching[s.Name] {
			blind = append(blind, s.Name)
		}
	}
	if len(blind) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no failure seen and the log is not known to reach Wazuh: "+strings.Join(blind, ", "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("no origin failed more than %d times within %s", in.MaxAttempts, originSpan)}
}

func origin(o string) string {
	if o == "" {
		return "unknown origin"
	}
	return o
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

package opacc5

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

const originSpan = 15 * time.Minute

type EV03Input struct {
	Services []Service

	Bursts   []source.Burst
	Failures []source.ServiceEvent

	Reaching map[string]bool

	MaxAttempts        int
	MaxAttemptsProblem string
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-03: "+in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

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

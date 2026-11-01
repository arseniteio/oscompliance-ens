package opacc5

import (
	"sort"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

const originSpan = 15 * time.Minute

type EV03Input struct {
	Services []Service

	Bursts   []source.Burst
	Failures []source.ServiceEvent

	Reaching map[string]bool

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	times := map[string][]time.Time{}
	for _, f := range in.Failures {
		key := f.Service + " " + origin(f.Origen)
		times[key] = append(times[key], f.Time)
	}

	var failing []catalog.Message
	failed := map[string]int{}

	for _, b := range in.Bursts {

		failed[b.Service] += b.Total
		if b.AtMost <= in.MaxAttempts {
			continue
		}

		key := b.Service + " " + origin(b.Key)
		if n := maxWithin(times[key], originSpan); n > in.MaxAttempts {
			failing = append(failing, catalog.Says("opacc5.failures_within", "origin", key, "count", n, "minutes", int(originSpan.Minutes())))
		}
	}

	if len(failing) > 0 {
		catalog.SortMessages(failing)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.origins_with_more_than_a_failures_b", "a", in.MaxAttempts, "b", failing))
	}

	var blind []string
	for _, s := range in.Services {
		if failed[s.Name] == 0 && !in.Reaching[s.Name] {
			blind = append(blind, s.Name)
		}
	}
	if len(blind) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.no_failure_seen_and_the_log_is_not_known", "a", blind))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.no_origin_failed_more_than_a_times_withi", "a", in.MaxAttempts, "b", int(originSpan.Minutes())))
}

func origin(o string) string {
	if o == "" {
		return "?"
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

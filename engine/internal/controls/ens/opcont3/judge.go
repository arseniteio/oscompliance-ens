package opcont3

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Test struct {
	Start, End   time.Time
	Kind         string
	Scenario     string
	Systems      []string
	Result       string
	Deficiencies int
}

func (t Test) Exercised() bool { return t.Kind == "parcial" || t.Kind == "simulacro" }

func (t Test) Involves(machine string) bool {
	return slices.ContainsFunc(t.Systems, func(s string) bool { return strings.EqualFold(s, machine) })
}

func ParseTests(rows []string) []Test {
	var out []Test
	for _, r := range rows {
		c := opcont2.Cells(r, 8)
		start, ok := opcont2.Date(c[0])
		if !ok {
			continue
		}
		end, ok := opcont2.Date(c[1])
		if !ok || end.Before(start) {
			end = start
		}
		var systems []string
		for _, s := range strings.Split(c[4], ",") {
			if s = strings.TrimSpace(s); s != "" {
				systems = append(systems, s)
			}
		}
		n, _ := strconv.Atoi(c[6])
		out = append(out, Test{Start: start, End: end, Kind: kind(c[2]), Scenario: c[3], Systems: systems, Result: kind(c[5]), Deficiencies: n})
	}
	slices.SortFunc(out, func(a, b Test) int { return a.Start.Compare(b.Start) })
	return out
}

func kind(v string) string { return strings.ReplaceAll(opcont2.Person(v), " ", "_") }

func Since(tests []Test, from time.Time) []Test {
	var out []Test
	for _, t := range tests {
		if !t.Start.Before(from) {
			out = append(out, t)
		}
	}
	return out
}

func JudgeEV01(period []Test, kinds []string) verdict.Judgement {

	planned := slices.ContainsFunc(kinds, func(r string) bool {
		k := kind(opcont2.Cells(r, 1)[0])
		return k == "parcial" || k == "simulacro"
	})
	if !planned {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont3.none_planned"))
	}
	i := slices.IndexFunc(period, Test.Exercised)
	if i < 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont3.none_exercised", "count", len(period)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.exercised", "count", len(period), "date", period[i].Start.Format("2006-01-02"), "kind", period[i].Kind))
}

func JudgeEV02(tests []Test, kinds, scenarios []string, months int, now time.Time) verdict.Judgement {

	last := func(match func(Test) bool) time.Time {
		var t time.Time
		for _, x := range tests {
			if match(x) && x.Start.After(t) {
				t = x.Start
			}
		}
		return t
	}
	due := func(t time.Time, m int) bool { return t.IsZero() || t.AddDate(0, m, 0).Before(now) }

	var overdue []catalog.Message
	if t := last(func(Test) bool { return true }); due(t, months) {
		overdue = append(overdue, catalog.Says("opcont3.item_overdue", "name", "plan", "months", months))
	}
	for _, r := range kinds {
		c := opcont2.Cells(r, 3)
		m, err := strconv.Atoi(c[2])
		if err != nil || m < 1 {
			m = months
		}
		k := kind(c[0])
		if due(last(func(x Test) bool { return x.Kind == k }), m) {
			overdue = append(overdue, catalog.Says("opcont3.item_overdue", "name", c[0], "months", m))
		}
	}
	for _, r := range scenarios {
		s := opcont2.Cells(r, 1)[0]
		if due(last(func(x Test) bool { return opcont2.Person(x.Scenario) == opcont2.Person(s) }), months) {
			overdue = append(overdue, catalog.Says("opcont3.item_overdue", "name", s, "months", months))
		}
	}
	if len(overdue) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont3.overdue", "list", overdue))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.periodic", "kinds", len(kinds), "scenarios", len(scenarios), "months", months))
}

func Downtime(records []source.MonitoringRecord, from, to time.Time) (longest time.Duration, restored, ok bool) {

	active := map[time.Time]bool{}
	var times []time.Time
	for _, r := range records {
		if r.Time.Before(from) || r.Time.After(to) {
			continue
		}
		if _, seen := active[r.Time]; !seen {
			times = append(times, r.Time)
		}
		active[r.Time] = active[r.Time] || r.Status == "active"
	}
	if len(times) == 0 {
		return 0, false, false
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })

	var down time.Time
	for _, t := range times {
		switch {
		case !active[t] && down.IsZero():
			down = t
		case active[t] && !down.IsZero():
			longest = max(longest, t.Sub(down))
			down = time.Time{}
		}
	}
	if !down.IsZero() {
		longest = max(longest, times[len(times)-1].Sub(down))
	}
	return longest, active[times[len(times)-1]], true
}

const followUp = 24 * time.Hour

type Measured struct {
	Test     Test
	Down     time.Duration
	Restored bool
	Seen     bool
}

func JudgeEV03(measured []Measured) verdict.Judgement {
	var unseen []string
	for _, m := range measured {
		if !m.Seen {
			unseen = append(unseen, m.Test.Start.Format("2006-01-02"))
		}
	}
	if len(unseen) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opcont3.unmeasured", "list", unseen))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.measured", "count", len(measured)))
}

func JudgeEV04(measured []Measured, rto []string, machine string) verdict.Judgement {

	if len(measured) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.not_tested"))
	}
	i := slices.IndexFunc(rto, func(r string) bool { return strings.EqualFold(opcont2.Cells(r, 1)[0], machine) })
	if i < 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opcont3.no_rto", "machine", machine))
	}
	c := opcont2.Cells(rto[i], 3)
	hours, err := strconv.ParseFloat(strings.ReplaceAll(c[1], ",", "."), 64)
	if err != nil {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_number", "value", c[1]))
	}
	tolerance, _ := strconv.Atoi(c[2])
	limit := time.Duration(hours*float64(time.Hour)) + time.Duration(tolerance)*time.Minute

	var missed []catalog.Message
	for _, m := range measured {
		if !m.Seen {
			continue
		}
		if m.Down > limit || !m.Restored {
			missed = append(missed, catalog.Says("opcont3.item_down", "date", m.Test.Start.Format("2006-01-02"), "down", m.Down.Round(time.Minute).String(), "result", m.Test.Result))
		}
	}
	if len(missed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont3.rto_missed", "rto", limit.String(), "list", missed))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.rto_met", "count", len(measured), "rto", limit.String()))
}

func JudgeEV05(tests []Test, rows []string, now time.Time) verdict.Judgement {

	var newest time.Time
	if len(tests) > 0 {
		newest = tests[len(tests)-1].Start.UTC().Truncate(24 * time.Hour)
	}

	followed := map[string]int{}
	var late []catalog.Message
	for _, r := range rows {
		c := opcont2.Cells(r, 7)
		test, _ := opcont2.Date(c[1])
		followed[test.Format("2006-01-02")]++
		if strings.EqualFold(c[4], "cerrada") {
			continue
		}
		deadline, ok := opcont2.Date(c[3])
		switch {
		case ok && deadline.Before(now):
			late = append(late, catalog.Says("opcont3.item_late", "name", c[0], "date", c[3]))
		case test.Before(newest):
			late = append(late, catalog.Says("opcont3.item_outlived", "name", c[0], "date", newest.Format("2006-01-02")))
		}
	}
	for _, t := range tests {
		if d := t.Start.Format("2006-01-02"); t.Deficiencies > followed[d] {
			late = append(late, catalog.Says("opcont3.item_unfollowed", "date", d, "declared", t.Deficiencies, "followed", followed[d]))
		}
	}
	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont3.deficiencies_open", "list", late))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont3.deficiencies_followed", "count", len(rows)))
}

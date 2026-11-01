// Package opexp9 judges op.exp.9, the record of incident management, over op.exp.7's incident register.
package opexp9

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Counter counts the alerts of the machine between two times.
type Counter func(from, to time.Time) (int, error)

func JudgeEV01(incidents []opexp7.Incident, count Counter) verdict.Judgement {

	var lost []string
	for _, in := range incidents {
		opened := in.Opened()
		n, err := count(opened.Add(-24*time.Hour), opened.Add(time.Hour))
		if err != nil {
			return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
		}
		if n == 0 {
			lost = append(lost, in.ID)
		}
	}
	if len(lost) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.events_lost", "list", lost))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.events_kept", "count", len(incidents)))
}

// Due are the phases of P-02 (`fase | contenido | exigible_desde_horas`) and from how many hours of
// duration each is due.
func Due(rows []string) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		h, err := strconv.Atoi(strings.TrimSpace(c[2]))
		if err != nil {
			h = 0
		}
		if name := strings.ToLower(strings.TrimSpace(c[0])); name != "" {
			out[name] = h
		}
	}
	return out
}

func JudgeEV02(incidents []opexp7.Incident, due map[string]int, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	var missing []catalog.Message
	checked := 0
	for _, in := range incidents {
		closed := in.Closed()
		if closed.IsZero() {
			continue
		}
		checked++
		lasted := closed.Sub(in.Opened())
		var lack []string
		for phase, from := range due {
			if lasted >= time.Duration(from)*time.Hour && !in.Has(phase) {
				lack = append(lack, phase)
			}
		}
		if len(lack) > 0 {
			slices.Sort(lack)
			missing = append(missing, catalog.Says("item.name_list", "name", in.ID, "list", lack))
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.reports_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.reports", "count", checked))
}

// JudgeEV04 needs the changes of the machine during each incident covered by requests of op.exp.5.
func JudgeEV04(incidents []opexp7.Incident, changes []opexp5.Change, requests []opexp5.Request, machine string, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	var during []opexp5.Change
	for _, c := range changes {
		if slices.ContainsFunc(incidents, func(in opexp7.Incident) bool { return !c.Time.Before(in.Opened()) && !c.Time.After(in.End(now)) }) {
			during = append(during, c)
		}
	}
	if bare := opexp5.Uncovered(during, requests, machine); len(bare) > 0 {
		list := make([]string, len(bare))
		for i, c := range bare {
			list[i] = c.String()
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.changes_unrecorded", "list", list))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.changes_recorded", "count", len(during)))
}

func legal(in opexp7.Incident) bool {
	v := in.Field(func(p opexp7.Phase) string { return p.Legal })
	return v == "si" || v == "sí"
}

func JudgeEV05(incidents []opexp7.Incident, manager *fact.WazuhAgentConfig, now time.Time) verdict.Judgement {

	var legalOnes []opexp7.Incident
	var unreferenced []string
	for _, in := range incidents {
		if !legal(in) {
			continue
		}
		legalOnes = append(legalOnes, in)
		if in.Field(func(p opexp7.Phase) string { return p.Reference }) == "" {
			unreferenced = append(unreferenced, in.ID)
		}
	}
	if len(unreferenced) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.legal_unreferenced", "list", unreferenced))
	}
	if len(legalOnes) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.no_legal"))
	}
	return opexp7.JudgeEV05(legalOnes, manager, now)
}

// JudgeEV07 needs alerts of the machine kept for every day of the incidents still open or legally relevant.
func JudgeEV07(incidents []opexp7.Incident, count Counter, now time.Time) verdict.Judgement {

	var lost []string
	checked := 0
	for _, in := range incidents {
		if !in.Closed().IsZero() && !legal(in) {
			continue
		}
		checked++
		for d := in.Opened().UTC().Truncate(24 * time.Hour); d.Before(in.End(now)); d = d.AddDate(0, 0, 1) {
			n, err := count(d, d.AddDate(0, 0, 1))
			if err != nil {
				return passes.Gap(verdict.CauseCollection, catalog.Says("gap.query", "error", err.Error()))
			}
			if n == 0 {
				lost = append(lost, in.ID+" "+d.Format("2006-01-02"))
			}
		}
	}
	if len(lost) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.period_lost", "list", lost))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.period_kept", "count", checked))
}

// JudgeEV08 needs, after a closed incident whose severity P-07 lists, the review of auditable events in time.
func JudgeEV08(incidents []opexp7.Incident, rows []string, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	limits := map[string]int{}
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 2 {
			c = append(c, "")
		}
		if d, err := strconv.Atoi(strings.TrimSpace(c[1])); err == nil {
			limits[opexp7.Severity(c[0])] = d
		}
	}

	var late []string
	checked := 0
	for _, in := range incidents {
		closed := in.Closed()
		limit, ok := limits[in.Severity()]
		if closed.IsZero() || !ok {
			continue
		}
		checked++
		review := time.Time{}
		for _, p := range in.Phases {
			if !p.Review.IsZero() {
				review = p.Review
			}
		}
		deadline := closed.Add(time.Duration(limit) * 24 * time.Hour)
		if (review.IsZero() && now.After(deadline)) || (!review.IsZero() && review.After(deadline)) {
			late = append(late, in.ID)
		}
	}
	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.review_missing", "list", late))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.reviewed", "count", checked))
}

func JudgeEV09(incidents []opexp7.Incident) verdict.Judgement {
	var incomplete []string
	for _, in := range incidents {
		switch {
		case in.Field(func(p opexp7.Phase) string { return p.Reference }) == "":
			incomplete = append(incomplete, in.ID+" (referencia)")
		case !in.Has("inicial"):
			incomplete = append(incomplete, in.ID+" (inicial)")
		}
	}
	if len(incomplete) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp9.record_incomplete", "list", incomplete))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp9.record_complete", "count", len(incidents)))
}

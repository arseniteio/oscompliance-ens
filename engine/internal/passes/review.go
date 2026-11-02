package passes

import (
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func Review(rows []string, rowsProblem catalog.Message, register string, maxDays int, daysProblem catalog.Message, period string, now time.Time) (verdict.Judgement, time.Time) {

	if !daysProblem.IsZero() {
		return Gap(verdict.CauseConfiguration, daysProblem), time.Time{}
	}
	if !rowsProblem.IsZero() {
		return Gap(verdict.CauseConfiguration, rowsProblem), time.Time{}
	}

	var newest time.Time
	var row string
	var bad []catalog.Message

	for _, r := range rows {
		date := strings.TrimSpace(strings.Split(r, "|")[0])
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, date); err != nil {
				bad = append(bad, catalog.Raw(date))
				continue
			}
		}
		if t.After(now) {
			bad = append(bad, catalog.Says("review.future_date", "date", date))
			continue
		}
		if t.After(newest) {
			newest, row = t, strings.TrimSpace(r)
		}
	}

	if newest.IsZero() {
		if len(bad) > 0 {
			return Gap(verdict.CauseEvidence, catalog.Says("review.no_usable_date", "dates", bad)), time.Time{}
		}
		return Gap(verdict.CauseConfiguration, catalog.Says("review.empty", "param", register)), time.Time{}
	}

	age := int(now.Sub(newest).Hours() / 24)
	if age > maxDays {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("review.overdue", "days", age, "param", period, "max", maxDays, "row", row)), newest
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("review.recent", "days", age, "param", period, "max", maxDays, "row", row)), newest
}

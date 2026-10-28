package opacc5

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV01Input struct {
	Services []Service
	Now      time.Time

	MinDays        int
	MinDaysProblem string
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if in.MinDaysProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_08_a", "a", in.MinDaysProblem))
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var short, unknown, kept []string

	for _, s := range in.Services {

		oldest := s.Span.Oldest
		if s.Span.Count == 0 {
			oldest = time.Time{}
		}
		if s.Log != nil && s.Log.EarliestEvent != "" {
			if t, err := time.Parse(time.RFC3339, s.Log.EarliestEvent); err == nil && (oldest.IsZero() || t.Before(oldest)) {
				oldest = t
			}
		}

		if oldest.IsZero() {
			unknown = append(unknown, s.Name+": no event in the index and no readable line on disk")
			continue
		}

		d := int(in.Now.Sub(oldest).Hours() / 24)
		item := fmt.Sprintf("%s (%d days, since %s)", s.Name, d, oldest.UTC().Format("2006-01-02"))

		if d < in.MinDays {
			short = append(short, item)
		} else {
			kept = append(kept, item)
		}
	}

	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.access_log_kept_less_than_a_days_b", "a", in.MinDays, "b", strings.Join(short, ", ")))
	}
	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.a", "a", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.access_log_kept_at_least_a_days_b", "a", in.MinDays, "b", strings.Join(kept, ", ")))
}

func noService() verdict.Judgement {
	return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.no_external_user_service_on_this_machine"))
}

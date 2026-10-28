package opacc5

import (
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV01Input struct {
	Services []Service
	Now      time.Time

	MinDays        int
	MinDaysProblem catalog.Message
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if !in.MinDaysProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MinDaysProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var short, unknown, kept []catalog.Message

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
			unknown = append(unknown, catalog.Says("opacc5.no_log_age", "service", s.Name))
			continue
		}

		d := int(in.Now.Sub(oldest).Hours() / 24)
		item := catalog.Says("opacc5.log_age", "service", s.Name, "days", d, "since", oldest.UTC().Format("2006-01-02"))

		if d < in.MinDays {
			short = append(short, item)
		} else {
			kept = append(kept, item)
		}
	}

	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.access_log_kept_less_than_a_days_b", "a", in.MinDays, "b", short))
	}
	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.access_log_kept_at_least_a_days_b", "a", in.MinDays, "b", kept))
}

func noService() verdict.Judgement {
	return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.no_external_user_service_on_this_machine"))
}

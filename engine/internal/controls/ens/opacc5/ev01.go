package opacc5

import (
	"fmt"
	"strings"
	"time"

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
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-08: "+in.MinDaysProblem)
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("access log kept less than %d days: %s", in.MinDays, strings.Join(short, ", "))}
	}
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("access log kept at least %d days: %s", in.MinDays, strings.Join(kept, ", "))}
}

func noService() verdict.Judgement {
	return passes.NotEvaluable(verdict.CauseConfiguration, "no external-user service on this machine: none in P-02 and none read by the agent")
}

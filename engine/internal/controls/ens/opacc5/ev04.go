package opacc5

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV04Input struct {
	Services []Service
	Accounts []source.ServiceAccount
	Now      time.Time

	MaxAge        int
	MaxAgeProblem string
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if in.MaxAgeProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_05_a", "a", in.MaxAgeProblem))
	}
	if len(in.Services) == 0 {
		return noService()
	}

	oldest := map[string]time.Time{}
	for _, s := range in.Services {
		if s.Span.Count > 0 {
			oldest[s.Name] = s.Span.Oldest
		}
	}

	limit := time.Duration(in.MaxAge) * 24 * time.Hour
	var old, unknown []string
	active := 0

	for _, a := range in.Accounts {

		last := a.LastSuccess
		if a.LastChange.After(last) {
			last = a.LastChange
		}
		if last.IsZero() || (!a.LastDisabled.IsZero() && !a.LastDisabled.Before(last)) {
			continue
		}
		active++

		who := a.Service + " " + a.User

		switch {

		case !a.LastChange.IsZero():
			if age := in.Now.Sub(a.LastChange); age > limit {
				old = append(old, fmt.Sprintf("%s (changed %d days ago)", who, int(age.Hours()/24)))
			}

		case !oldest[a.Service].IsZero() && in.Now.Sub(oldest[a.Service]) > limit:
			old = append(old, fmt.Sprintf("%s (no change in the %d days the index keeps)", who, int(in.Now.Sub(oldest[a.Service]).Hours()/24)))
		default:
			unknown = append(unknown, who)
		}
	}

	if len(old) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.credentials_older_than_a_days_b", "a", in.MaxAge, "b", strings.Join(old, ", ")))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_credential_change_recorded_yet_for_a", "a", unknown))
	}
	if active == 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_account_of_the_services_logged_in_or"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_accounts_every_credential_changed_with", "a", active, "b", in.MaxAge))
}

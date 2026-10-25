package opacc5

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV04Input is what EV-04 (periodic credential change) needs.
type EV04Input struct {
	Services []Service
	Accounts []source.ServiceAccount
	Now      time.Time

	// MaxAge is P-05 in days; MaxAgeProblem says why it cannot be used.
	MaxAge        int
	MaxAgeProblem string
}

// JudgeEV04 judges EV-04 as described in catalog/docs/contracts/op.acc.5.md.
// Accounts are those that logged in or changed their credential and were not
// disabled afterwards, as far back as the index goes:
//
//  1. P-05 unusable or no service: NOT_EVALUABLE, CONFIGURATION.
//  2. The last credential change older than P-05: NON_COMPLIANT.
//  3. No change recorded: the credential is at least as old as the oldest
//     event the index keeps of the service; when that is beyond P-05,
//     NON_COMPLIANT (v1 left such accounts unknown forever), otherwise
//     NOT_EVALUABLE, EVIDENCE.
//  4. No account: NOT_EVALUABLE, EVIDENCE. Otherwise COMPLIANT.
func JudgeEV04(in EV04Input) verdict.Judgement {

	// 1. Parameter and subject.
	if in.MaxAgeProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+in.MaxAgeProblem)
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
		// 2. Measured.
		case !a.LastChange.IsZero():
			if age := in.Now.Sub(a.LastChange); age > limit {
				old = append(old, fmt.Sprintf("%s (changed %d days ago)", who, int(age.Hours()/24)))
			}
		// 3. At least as old as the index.
		case !oldest[a.Service].IsZero() && in.Now.Sub(oldest[a.Service]) > limit:
			old = append(old, fmt.Sprintf("%s (no change in the %d days the index keeps)", who, int(in.Now.Sub(oldest[a.Service]).Hours()/24)))
		default:
			unknown = append(unknown, who)
		}
	}

	if len(old) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("credentials older than %d days: %s", in.MaxAge, strings.Join(old, ", "))}
	}

	// 4. What could not be dated.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "no credential change recorded yet for: "+strings.Join(unknown, ", "))
	}
	if active == 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "no account of the services logged in or changed its credential")
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d accounts, every credential changed within %d days", active, in.MaxAge)}
}

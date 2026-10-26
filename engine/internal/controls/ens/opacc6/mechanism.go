package opacc6

import (
	"regexp"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// mechanismRequirements are the requirements of the four reinforcements,
// with the mechanisms (P-01) under which each one applies.
var mechanismRequirements = map[string][]string{
	"op.acc.6.r1.1": {"R1"},
	"op.acc.6.r1.2": {"R1", "R2"},
	"op.acc.6.r2.1": {"R2"},
	"op.acc.6.r3.1": {"R3"},
	"op.acc.6.r3.2": {"R3"},
	"op.acc.6.r4.1": {"R4"},
	"op.acc.6.r4.2": {"R4"},
}

var mechanismValue = regexp.MustCompile(`^R([1-4])\b`)

// Mechanism reads P-01: "R1" to "R4", "" with the problem when it cannot be
// used.
func Mechanism(values []string, err error) (mechanism, problem string) {

	if err != nil {
		return "", err.Error()
	}

	if len(values) == 0 {
		return "", "not set"
	}

	m := mechanismValue.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(values[0])))
	if m == nil {
		return "", "\"" + values[0] + "\" is not R1, R2, R3 or R4"
	}

	return "R" + m[1], ""
}

// MechanismDecisions are the decisions P-01 takes on the seven reinforcement
// requirements: a requirement of a mechanism not chosen is NOT_APPLICABLE;
// without a usable P-01 every one of them counts against, and no P-ATT
// attestation can prove a reinforcement nobody chose (v1 accepted one). The
// requirements of the chosen mechanism get no decision: their evidences, or
// P-ATT for the certificate ones, prove them.
func MechanismDecisions(mechanism, problem string) map[string]verdict.Judgement {

	decisions := map[string]verdict.Judgement{}

	for id, mechanisms := range mechanismRequirements {

		if problem != "" {
			decisions[id] = passes.NotEvaluable(verdict.CauseConfiguration, "P-01 "+problem+": the mechanism is unknown")
			continue
		}

		applies := false
		for _, m := range mechanisms {
			if m == mechanism {
				applies = true
			}
		}

		if !applies {
			decisions[id] = verdict.Judgement{
				Status: verdict.NotApplicable,
				Reason: "applies with " + strings.Join(mechanisms, " or ") + "; P-01 is " + mechanism,
			}
		}
	}

	return decisions
}

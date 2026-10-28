package opacc6

import (
	"regexp"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

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

func MechanismDecisions(mechanism, problem string) map[string]verdict.Judgement {

	decisions := map[string]verdict.Judgement{}

	for id, mechanisms := range mechanismRequirements {

		if problem != "" {
			decisions[id] = passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_01_a_the_mechanism_is_unknown", "a", problem))
			continue
		}

		applies := false
		for _, m := range mechanisms {
			if m == mechanism {
				applies = true
			}
		}

		if !applies {
			decisions[id] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("opacc6.applies_with_a_p_01_is_b", "a", mechanisms, "b", mechanism))
		}
	}

	return decisions
}

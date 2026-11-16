package opacc6

import (
	"regexp"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
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

func Mechanism(values []string, err error) (mechanism string, problem catalog.Message) {

	if err != nil {
		return "", passes.Param("P-01", err)
	}

	if len(values) == 0 {
		return "", catalog.Says("param.not_set", "param", "P-01")
	}

	m := mechanismValue.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(values[0])))
	if m == nil {
		return "", catalog.Says("opacc5.not_mechanism", "value", values[0])
	}

	return "R" + m[1], catalog.Message{}
}

func MechanismDecisions(mechanism string, problem catalog.Message) map[string]verdict.Judgement {

	decisions := map[string]verdict.Judgement{}

	for id, mechanisms := range mechanismRequirements {

		if !problem.IsZero() {
			decisions[id] = passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.mechanism_unknown", "problem", problem))
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

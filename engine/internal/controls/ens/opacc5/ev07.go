package opacc5

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func Reinforcement(factors []string) string {

	has := map[string]bool{}
	for _, f := range factors {
		has[strings.ToLower(strings.TrimSpace(f))] = true
	}
	second := has["pin"] || has["biometria"]

	switch {
	case has["tarjeta"] && second:
		return "R4"
	case has["certificado"] && second:
		return "R3"
	case has["password"] && has["otp"]:
		return "R2"
	case has["password"] && len(has) == 1:
		return "R1"
	}

	return ""
}

type EV07Input struct {
	Services []Service
	Methods  []source.MethodCount

	Mechanism string
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}
	if in.Mechanism == "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_01_not_usable_the_mechanism_to_compare"))
	}

	var other []catalog.Message
	unknown, total := 0, 0

	for _, m := range in.Methods {

		total += m.Count

		if m.Factors == "" {
			unknown += m.Count
			continue
		}

		if r := Reinforcement(strings.Split(m.Factors, "+")); r != in.Mechanism {
			class := catalog.Raw(r)
			if r == "" {
				class = catalog.Says("opacc5.no_mechanism")
			}
			other = append(other, catalog.Says("opacc5.login_method", "service", m.Service, "factors", m.Factors, "class", class, "count", m.Count))
		}
	}

	if len(other) > 0 {
		catalog.SortMessages(other)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.logins_not_by_a_b", "a", in.Mechanism, "b", other))
	}
	if unknown > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.a_successful_logins_without_factors_in_t", "a", unknown))
	}
	if total == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.no_successful_login_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_successful_logins_all_by_b", "a", total, "b", in.Mechanism))
}

package opacc5

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
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
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-01 not usable: the mechanism to compare with is unknown")
	}

	var other []string
	unknown, total := 0, 0

	for _, m := range in.Methods {

		total += m.Count

		if m.Factors == "" {
			unknown += m.Count
			continue
		}

		if r := Reinforcement(strings.Split(m.Factors, "+")); r != in.Mechanism {
			class := r
			if class == "" {
				class = "no ENS mechanism"
			}
			other = append(other, fmt.Sprintf("%s %s (%s, %d logins)", m.Service, m.Factors, class, m.Count))
		}
	}

	if len(other) > 0 {
		sort.Strings(other)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "logins not by " + in.Mechanism + ": " + strings.Join(other, "; ")}
	}
	if unknown > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, fmt.Sprintf("%d successful logins without factors in the log", unknown))
	}
	if total == 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no successful login in the window")
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d successful logins, all by %s", total, in.Mechanism)}
}

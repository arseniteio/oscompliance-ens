package opacc5

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Reinforcement classifies a set of factors as the ENS mechanisms: R4 a
// card with PIN or biometrics, R3 a certificate with PIN or biometrics, R2 a
// password with an OTP, R1 a password alone; "" for anything else.
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

// EV07Input is what EV-07 (the mechanism actually used) needs.
type EV07Input struct {
	Services []Service
	Methods  []source.MethodCount // successful logins of the window
	// Mechanism is P-01 (R1 to R4); "" leaves the evidence unjudged.
	Mechanism string
}

// JudgeEV07 judges EV-07 as described in catalog/docs/contracts/op.acc.5.md:
//
//  1. No service: NOT_EVALUABLE, CONFIGURATION. P-01 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. Each successful login is classified by its factors. One that is not
//     the P-01 mechanism, weaker or another: NON_COMPLIANT.
//  3. Logins without factors: NOT_EVALUABLE, EVIDENCE. No login in the
//     window: NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
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

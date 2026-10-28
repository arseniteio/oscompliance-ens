package opacc5

import (
	"regexp"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/aggregate"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

var mechanismRequirements = map[string]string{
	"op.acc.5.r1.1": "R1", "op.acc.5.r1.2": "R1",
	"op.acc.5.r2.1": "R2",
	"op.acc.5.r3.1": "R3", "op.acc.5.r3.2": "R3", "op.acc.5.r3.3": "R3",
	"op.acc.5.r4.1": "R4", "op.acc.5.r4.2": "R4", "op.acc.5.r4.3": "R4",
}

var mechanismValue = regexp.MustCompile(`^R([1-4])\b`)

func Mechanism(values []string, err error) (string, string) {

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

type DecisionInput struct {
	Level string

	Mechanism, MechanismProblem string

	Policies map[string]Policy
	Services []Service

	ProcedureProblem string

	LastAccess        bool
	LastAccessProblem string

	Exclusion *aggregate.Attestation

	Evidence map[string]verdict.Judgement
}

func ParseExclusion(rows []string) *aggregate.Attestation {

	for reason, a := range aggregate.ParseAttestations(rows) {
		if a.Sufficient() {
			a.Reference = reason + ": " + a.Reference
			return &a
		}
	}

	return nil
}

func Decisions(in DecisionInput, requirements []string) map[string]verdict.Judgement {

	d := map[string]verdict.Judgement{}

	if in.Exclusion != nil && len(in.Services) == 0 {
		reason := "excluded by the Statement of Applicability: " + in.Exclusion.Reference
		for _, r := range requirements {
			d[r] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("opacc5.a", "a", reason))
		}
		return d
	}

	for req, m := range mechanismRequirements {
		switch {
		case in.MechanismProblem != "":
			d[req] = passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_01_a_the_mechanism_is_unknown", "a", in.MechanismProblem))
		case m != in.Mechanism:
			d[req] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("opacc5.applies_with_a_p_01_is_b", "a", m, "b", in.Mechanism))
		case m == "R1" && in.Level != "" && in.Level != "BAJO":
			d[req] = verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.p_01_is_r1_a_password_alone_which_the_en", "a", in.Level))
		}
	}

	failed := func(ids ...string) bool {
		for _, id := range ids {
			if in.Evidence[id].Status == verdict.NonCompliant {
				return true
			}
		}
		return false
	}

	if _, decided := d["op.acc.5.r1.2"]; !decided && !failed("EV-02") {
		if j, ok := complexity(in); ok {
			d["op.acc.5.r1.2"] = j
		}
	}

	if in.ProcedureProblem != "" && !failed("EV-02", "EV-03") {
		d["op.acc.5.8"] = passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_04_reactivation_procedure_a", "a", in.ProcedureProblem))
	}

	switch {
	case in.LastAccessProblem != "":
		d["op.acc.5.r5.2"] = passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_09_a", "a", in.LastAccessProblem))
	case !in.LastAccess:
		d["op.acc.5.r5.2"] = verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.p_09_says_the_service_does_not_tell_user"))
	}

	return d
}

func complexity(in DecisionInput) (verdict.Judgement, bool) {

	var weak, missing []string

	for _, s := range in.Services {
		p := in.Policies[s.Name]
		switch {
		case p.Complexity == "desactivada" || (p.Found && p.MinLength <= 0 && p.Complexity != ""):
			weak = append(weak, s.Name)
		case p.Complexity != "activada" || p.MinLength <= 0:
			missing = append(missing, s.Name)
		}
	}

	switch {
	case len(weak) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.password_complexity_off_or_no_minimum_le", "a", weak)), true
	case len(missing) > 0:
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_password_policy_with_complexity_and_a", "a", missing)), true
	}

	return verdict.Judgement{}, false
}

package opacc5

import (
	"regexp"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/aggregate"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// mechanismRequirements are the requirements of the four reinforcements,
// each under the mechanism (P-01) it belongs to.
var mechanismRequirements = map[string]string{
	"op.acc.5.r1.1": "R1", "op.acc.5.r1.2": "R1",
	"op.acc.5.r2.1": "R2",
	"op.acc.5.r3.1": "R3", "op.acc.5.r3.2": "R3", "op.acc.5.r3.3": "R3",
	"op.acc.5.r4.1": "R4", "op.acc.5.r4.2": "R4", "op.acc.5.r4.3": "R4",
}

var mechanismValue = regexp.MustCompile(`^R([1-4])\b`)

// Mechanism reads P-01: "R1" to "R4", or "" with the problem.
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

// DecisionInput is what the requirement decisions need besides the
// evidence verdicts.
type DecisionInput struct {
	Level string // active ENS level

	Mechanism, MechanismProblem string

	Policies map[string]Policy
	Services []Service

	// ProcedureProblem: P-04 (the reactivation procedure) cannot be used.
	ProcedureProblem string
	// LastAccess is P-09; LastAccessProblem says why it cannot be used.
	LastAccess        bool
	LastAccessProblem string

	// Exclusion is P-DA, the Statement of Applicability, when sufficient.
	Exclusion *aggregate.Attestation

	// Evidence verdicts of the agent: a measured failure decides before a
	// missing declaration.
	Evidence map[string]verdict.Judgement
}

// ParseExclusion reads P-DA, "motivo | referencia | enlace | fecha |
// responsable": the first row with a reason, a reference and a usable link.
func ParseExclusion(rows []string) *aggregate.Attestation {

	for reason, a := range aggregate.ParseAttestations(rows) {
		if a.Sufficient() {
			a.Reference = reason + ": " + a.Reference
			return &a
		}
	}

	return nil
}

// Decisions are the requirements op.acc.5 decides itself, as the plugin's
// policy does (section 5 of the contract):
//
//   - P-DA with a reference and a link, on a machine with no external-user
//     service: every requirement NOT_APPLICABLE. With a service it is
//     contradicted and ignored.
//   - P-01: requirements of other mechanisms NOT_APPLICABLE; unusable, all
//     nine NOT_EVALUABLE (no P-ATT proves a reinforcement nobody chose).
//     R1 above BAJO: r1.1 and r1.2 NON_COMPLIANT, a password alone is only
//     allowed at BAJO.
//   - r1.2 under R1: the declared password policy must have complexity on
//     and a minimum length.
//   - .8: P-04 must say how accounts are reactivated.
//   - r5.2: P-09 no is NON_COMPLIANT; unset NOT_EVALUABLE; yes leaves it to
//     P-ATT.
func Decisions(in DecisionInput, requirements []string) map[string]verdict.Judgement {

	d := map[string]verdict.Judgement{}

	// The Statement of Applicability.
	if in.Exclusion != nil && len(in.Services) == 0 {
		reason := "excluded by the Statement of Applicability: " + in.Exclusion.Reference
		for _, r := range requirements {
			d[r] = verdict.Judgement{Status: verdict.NotApplicable, Reason: reason}
		}
		return d
	}

	// The mechanism.
	for req, m := range mechanismRequirements {
		switch {
		case in.MechanismProblem != "":
			d[req] = passes.NotEvaluable(verdict.CauseConfiguration, "P-01 "+in.MechanismProblem+": the mechanism is unknown")
		case m != in.Mechanism:
			d[req] = verdict.Judgement{Status: verdict.NotApplicable, Reason: "applies with " + m + "; P-01 is " + in.Mechanism}
		case m == "R1" && in.Level != "" && in.Level != "BAJO":
			d[req] = verdict.Judgement{Status: verdict.NonCompliant, Reason: "P-01 is R1, a password alone, which the ENS only allows at BAJO; the level is " + in.Level}
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

	// r1.2 under R1 at BAJO: what the services declare, unless EV-02
	// already failed.
	if _, decided := d["op.acc.5.r1.2"]; !decided && !failed("EV-02") {
		if j, ok := complexity(in); ok {
			d["op.acc.5.r1.2"] = j
		}
	}

	// .8: the reactivation procedure must be documented; a measured
	// failure of EV-02 or EV-03 decides first.
	if in.ProcedureProblem != "" && !failed("EV-02", "EV-03") {
		d["op.acc.5.8"] = passes.NotEvaluable(verdict.CauseConfiguration, "P-04 (reactivation procedure): "+in.ProcedureProblem)
	}

	// r5.2: a function of the portal, declared in P-09.
	switch {
	case in.LastAccessProblem != "":
		d["op.acc.5.r5.2"] = passes.NotEvaluable(verdict.CauseConfiguration, "P-09: "+in.LastAccessProblem)
	case !in.LastAccess:
		d["op.acc.5.r5.2"] = verdict.Judgement{Status: verdict.NonCompliant, Reason: "P-09 says the service does not tell users of their last access"}
	}

	return d
}

// complexity decides r1.2 from the declared password policies; ok is false
// when the policies leave it to EV-02.
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "password complexity off or no minimum length: " + strings.Join(weak, ", ")}, true
	case len(missing) > 0:
		return passes.NotEvaluable(verdict.CauseEvidence, "no password policy with complexity and a minimum length declared by: "+strings.Join(missing, ", ")), true
	}

	return verdict.Judgement{}, false
}

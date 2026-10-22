// Package aggregate turns evidence verdicts into requirement and control
// verdicts with the plugin's audit rules (requirement-evaluator.ts,
// control-evaluator.ts, verdict.ts):
//
//   - What cannot be proven counts against: an unmeasured requirement is
//     NON_COMPLIANT, marked not evidenced, with the causes of its evidences.
//   - A measured failure fails the whole requirement; there is no partial
//     credit at requirement level.
//   - NOT_APPLICABLE leaves the denominator.
//   - A requirement with no technical evidence is proven only by a document
//     (P-ATT attestation) and is marked attested.
package aggregate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Attestation is one P-ATT row: "requisito | referencia | enlace | fecha |
// responsable".
type Attestation struct {
	Reference   string
	Links       []string
	Date        string
	Responsible string
}

// Sufficient: a reference and at least one usable link, as the plugin.
func (a Attestation) Sufficient() bool {
	return a.Reference != "" && len(a.Links) > 0
}

// Requirement is the verdict of one requirement.
type Requirement struct {
	ID        string
	Status    verdict.Status // COMPLIANT, NON_COMPLIANT or NOT_APPLICABLE
	Evidenced bool
	Attested  bool
	Reason    string
}

// Control is the verdict of a control from its requirements.
type Control struct {
	Status     verdict.Status // COMPLIANT, NON_COMPLIANT, PARTIAL or NOT_APPLICABLE
	Score      *int           // nil when nothing applies
	Coverage   int            // measured / applicable, in %
	Applicable int
	Measured   int
	Unmeasured []string
}

// EvaluateRequirement judges one requirement from the verdicts of its
// evidences. An evidence the engine produced no verdict for (it could not
// read its facts) counts as NOT_EVALUABLE by COLLECTION, never as absent: a
// requirement must not comply on the evidences that happened to be read.
func EvaluateRequirement(req catalog.Requirement, level string, controlEnabled bool, evidences map[string]verdict.Judgement, attestation *Attestation) Requirement {

	out := Requirement{ID: req.ID}

	// Out of the denominator: disabled control, or a level it does not
	// apply at. Without a known level nothing is ruled out.
	if !controlEnabled {
		out.Status, out.Reason = verdict.NotApplicable, "control disabled in the configuration"
		return out
	}
	if level != "" && !req.AppliesAt(level) {
		reason := req.ApplicabilityReason
		if reason == "" {
			reason = fmt.Sprintf("applies at %s; active ENS level %s", strings.Join(req.Levels, ", "), level)
		}
		out.Status, out.Reason = verdict.NotApplicable, reason
		return out
	}

	// No technical evidence: only a document proves it.
	if len(req.EvidenceIDs) == 0 {
		if attestation != nil && attestation.Sufficient() {
			out.Status, out.Evidenced, out.Attested = verdict.Compliant, true, true
			out.Reason = "attested by document: " + attestation.Reference
			return out
		}
		out.Status = verdict.NonCompliant
		out.Reason = "not evidenced: no technical evidence exists and no P-ATT attestation with a reference and a usable link"
		return out
	}

	var failing, unmeasured, compliant []string

	for _, id := range req.EvidenceIDs {

		j, ok := evidences[id]
		if !ok {
			j = verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseCollection}
		}

		switch j.Status {
		case verdict.NotApplicable:
		case verdict.NonCompliant:
			failing = append(failing, id)
		case verdict.Compliant:
			compliant = append(compliant, id)
		default:
			unmeasured = append(unmeasured, fmt.Sprintf("%s (%s)", id, j.Cause))
		}
	}

	switch {
	case len(failing) > 0:
		// A measured failure fails the requirement, whatever else is missing.
		out.Status, out.Evidenced = verdict.NonCompliant, true
		out.Reason = "non-compliant evidence: " + strings.Join(failing, ", ")
	case len(unmeasured) > 0:
		out.Status = verdict.NonCompliant
		out.Reason = "not evidenced: " + strings.Join(unmeasured, ", ")
	case len(compliant) > 0:
		out.Status, out.Evidenced = verdict.Compliant, true
		out.Reason = "compliant evidence: " + strings.Join(compliant, ", ")
	default:
		// Every evidence is NOT_APPLICABLE: nothing measures the requirement.
		out.Status = verdict.NonCompliant
		out.Reason = "not evidenced: none of " + strings.Join(req.EvidenceIDs, ", ") + " applies"
	}

	return out
}

// EvaluateControl: all applicable compliant is COMPLIANT (100), all failing
// is NON_COMPLIANT, a mix is PARTIAL with the average score; nothing
// applicable is NOT_APPLICABLE with no score. The denominator is every
// applicable requirement, measured or not.
func EvaluateControl(reqs []Requirement) Control {

	var applicable []Requirement

	for _, r := range reqs {
		if r.Status != verdict.NotApplicable {
			applicable = append(applicable, r)
		}
	}

	if len(applicable) == 0 {
		return Control{Status: verdict.NotApplicable}
	}

	out := Control{Applicable: len(applicable)}
	sum, compliant := 0, 0

	for _, r := range applicable {
		if r.Evidenced {
			out.Measured++
		} else {
			out.Unmeasured = append(out.Unmeasured, r.ID)
		}
		if r.Status == verdict.Compliant {
			compliant++
			sum += 100
		}
	}

	out.Coverage = roundDiv(out.Measured*100, out.Applicable)

	score := roundDiv(sum, out.Applicable)
	out.Score = &score

	switch compliant {
	case out.Applicable:
		out.Status = verdict.Compliant
	case 0:
		out.Status = verdict.NonCompliant
	default:
		out.Status = verdict.Partial
	}

	return out
}

// roundDiv rounds a/b half away from zero, as JavaScript Math.round does for
// these positive values.
func roundDiv(a, b int) int {
	return (2*a + b) / (2 * b)
}

// ParseAttestations reads P-ATT rows: "requisito | referencia | enlace |
// fecha | responsable". Extra links go in the same cell separated by spaces,
// commas or semicolons. Rows without requirement or reference are ignored.
func ParseAttestations(rows []string) map[string]Attestation {

	out := map[string]Attestation{}

	for _, row := range rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		for len(cells) < 5 {
			cells = append(cells, "")
		}

		if cells[0] == "" || cells[1] == "" {
			continue
		}

		var links []string
		for _, link := range strings.FieldsFunc(cells[2], func(r rune) bool { return r == ' ' || r == ',' || r == ';' || r == '\t' }) {
			if usableLink(link) {
				links = append(links, link)
			}
		}

		out[cells[0]] = Attestation{Reference: cells[1], Links: links, Date: cells[3], Responsible: cells[4]}
	}

	return out
}

// placeholderHosts are the domains of the parameter's own example: copying it
// verbatim proves nothing.
var placeholderHosts = []string{"ejemplo.invalido", "example.invalid"}

// usableLink: http(s)://, file://, a network path (\\server\...) or an
// absolute path, as the plugin.
func usableLink(link string) bool {

	lower := strings.ToLower(link)

	if slices.ContainsFunc(placeholderHosts, func(h string) bool { return strings.Contains(lower, h) }) {
		return false
	}

	for _, prefix := range []string{"http://", "https://", "file://"} {
		if strings.HasPrefix(lower, prefix) && len(link) > len(prefix) {
			return true
		}
	}

	return strings.HasPrefix(link, `\\`) && len(link) > 2 || strings.HasPrefix(link, "/") && len(link) > 1
}

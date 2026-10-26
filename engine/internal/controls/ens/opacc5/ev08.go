package opacc5

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV08Input struct {
	Services     []Service
	Certificates []source.CertificateCount

	Rows        []string
	RowsProblem string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}
	if in.RowsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-07: "+in.RowsProblem)
	}

	admitted := map[string]map[string]bool{}
	for _, r := range in.Rows {
		issuer, checks, _ := strings.Cut(r, "|")
		set := map[string]bool{}
		for _, c := range strings.FieldsFunc(strings.ToLower(checks), func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			set[c] = true
		}
		admitted[strings.TrimSpace(issuer)] = set
	}

	var failing []string
	total := 0

	for _, c := range in.Certificates {

		total += c.Count
		issuer, revocation := c.Issuer, strings.ToLower(c.Revocation)

		checks, listed := admitted[issuer]

		switch {
		case !listed:
			failing = append(failing, fmt.Sprintf("%s: issuer %q not admitted in P-07 (%d logins)", c.Service, issuer, c.Count))
		case !checks[revocation]:
			failing = append(failing, fmt.Sprintf("%s: %s checked by %q, P-07 demands %s (%d logins)", c.Service, issuer, revocation, strings.Join(sortedKeys(checks), " or "), c.Count))
		}
	}

	if len(failing) > 0 {
		sort.Strings(failing)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}
	if total == 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no certificate login in the window")
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d certificate logins, issuers admitted and revocation checked as P-07 demands", total)}
}

func sortedKeys(set map[string]bool) []string {
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

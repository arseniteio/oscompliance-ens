package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type LoginInput struct {
	Forbidden params.Matcher

	ForbiddenProblem catalog.Message

	AuthSeen bool

	Logins []source.Login
}

func JudgeEV03(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-04", "opacc1.ev03.generic")
}

func JudgeEV05(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-03", "opacc1.ev05.service")
}

func noLoginIn(in LoginInput, paramID, kind string) verdict.Judgement {

	if !in.ForbiddenProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ForbiddenProblem)
	}

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, catalog.Says("gap.no_auth_events"))
	}

	counts := map[string]int{}

	for _, login := range in.Logins {
		if in.Forbidden.Match(login.Account) {
			counts[strings.ToLower(login.Account)]++
		}
	}

	if len(counts) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says(kind+"_logged", "accounts", countList(counts)))
	}

	if len(in.Logins) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says(kind+"_no_logins", "param", paramID))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says(kind+"_none",
		"logins", len(in.Logins), "methods", byMethod(in.Logins), "param", paramID))
}

func byMethod(logins []source.Login) string {

	counts := map[string]int{}

	for _, login := range logins {
		counts[login.Method]++
	}

	var names []string

	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)

	var parts []string

	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s %d", name, counts[name]))
	}

	return strings.Join(parts, ", ")
}

func countList(counts map[string]int) string {

	var names []string

	for name := range counts {
		names = append(names, name)
	}

	sort.Strings(names)

	var parts []string

	for _, name := range names {
		parts = append(parts, fmt.Sprintf("%s (%d)", name, counts[name]))
	}

	return strings.Join(parts, ", ")
}

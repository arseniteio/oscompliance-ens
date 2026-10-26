package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type LoginInput struct {
	Forbidden params.Matcher

	ForbiddenProblem string

	AuthSeen bool

	Logins []source.Login
}

func JudgeEV03(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-04", "generic")
}

func JudgeEV05(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-03", "service")
}

func noLoginIn(in LoginInput, paramID, kind string) verdict.Judgement {

	if in.ForbiddenProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, paramID+": "+in.ForbiddenProblem)
	}

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, "no authentication events from this agent in the lookback")
	}

	counts := map[string]int{}

	for _, login := range in.Logins {
		if in.Forbidden.Match(login.Account) {
			counts[strings.ToLower(login.Account)]++
		}
	}

	if len(counts) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: kind + " accounts authenticated: " + countList(counts),
		}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d logins in the window%s, none with a %s account", len(in.Logins), byMethod(in.Logins), paramID),
	}
}

func byMethod(logins []source.Login) string {

	if len(logins) == 0 {
		return ""
	}

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

	return " (" + strings.Join(parts, ", ") + ")"
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

package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// LoginInput is what the engine knows about one agent when judging EV-03 or
// EV-05: the same logins, checked against a different list. Logins come from
// Wazuh's own sshd and PAM alerts, not from our agent.
type LoginInput struct {
	// Forbidden is the parameter the logins are checked against (P-04 for
	// EV-03, P-03 for EV-05): a list or a regular expression. Unusable when
	// ForbiddenProblem is set.
	Forbidden params.Matcher
	// ForbiddenProblem says why the list cannot be used (not set, not a list,
	// regex); "" when it can.
	ForbiddenProblem string
	// AuthSeen: the agent sent at least one authentication event in the
	// lookback, so its authentication log reaches Wazuh.
	AuthSeen bool
	// Logins are the interactive logins in the window (sshd, console, su,
	// graphical), oldest first.
	Logins []source.Login
}

// JudgeEV03 judges EV-03 (no authentication with generic or shared accounts,
// P-04). Steps in noLoginIn.
func JudgeEV03(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-04", "generic")
}

// JudgeEV05 judges EV-05 (no interactive login with service accounts, P-03).
// Steps in noLoginIn.
func JudgeEV05(in LoginInput) verdict.Judgement {
	return noLoginIn(in, "P-03", "service")
}

// noLoginIn is the judgement shared by EV-03 and EV-05 (contract section 7):
//
//  1. ForbiddenProblem set: NOT_EVALUABLE, CONFIGURATION, reason "<param>: " + problem.
//  2. AuthSeen false: NOT_EVALUABLE, COLLECTION.
//  3. Any login whose account matches Forbidden (a list ignoring case, or a
//     whole-name regular expression): NON_COMPLIANT,
//     reason "<kind> accounts authenticated: a (2), b (1)".
//  4. Otherwise COMPLIANT, reason "N logins in the window (sshd 1, su 2),
//     none with a <param> account".
func noLoginIn(in LoginInput, paramID, kind string) verdict.Judgement {

	// 1. Without the list there is nothing to compare against.
	if in.ForbiddenProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, paramID+": "+in.ForbiddenProblem)
	}

	// 2. Silence only counts when the authentication log is known to arrive.
	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, "no authentication events from this agent in the lookback")
	}

	// 3. Logins with a forbidden account, counted per account. Lowercase
	// key, so "Admin" and "admin" are one account.
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

	// 4. The log arrives and no forbidden account logged in.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d logins in the window%s, none with a %s account", len(in.Logins), byMethod(in.Logins), paramID),
	}
}

// byMethod writes " (sshd 2, su 1)", or "" without logins.
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

// countList writes "a (2), b (1)", sorted by name: a map has no order.
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

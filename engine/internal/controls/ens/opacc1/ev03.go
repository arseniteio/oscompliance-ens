package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV03Input is what the engine knows about one agent when judging EV-03.
// Logins come from Wazuh's own sshd alerts, not from our agent.
type EV03Input struct {
	// Generic is P-04, the forbidden generic account names. Empty when
	// GenericProblem is set.
	Generic []string
	// GenericProblem says why P-04 cannot be used (not set, not a list,
	// regex); "" when it can.
	GenericProblem string
	// AuthSeen: the agent sent at least one authentication event in the
	// lookback, so its authentication log reaches Wazuh.
	AuthSeen bool
	// Logins are the successful sshd logins in the window, oldest first.
	Logins []source.Login
}

// JudgeEV03 judges EV-03 (no authentication with generic or shared accounts)
// as described in catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. GenericProblem set: NOT_EVALUABLE, CONFIGURATION, reason "P-04: " + problem.
//  2. AuthSeen false: NOT_EVALUABLE, COLLECTION, reason
//     "no authentication events from this agent in the lookback".
//  3. Any login whose Account is in Generic, ignoring case: NON_COMPLIANT.
//     Reason: "generic accounts authenticated: admin (2), guest (1)",
//     one entry per account, sorted by name, with how many logins.
//  4. Otherwise COMPLIANT, reason "N sshd logins in the window, none with a
//     P-04 account".
func JudgeEV03(in EV03Input) verdict.Judgement {

	// 1. Without P-04 there is nothing to compare against.
	if in.GenericProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, "P-04: "+in.GenericProblem)
	}

	// 2. Silence only counts when the authentication log is known to arrive.
	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, "no authentication events from this agent in the lookback")
	}

	// 3. Logins with a forbidden account, counted per account. Lowercase
	// key, so "Admin" and "admin" are one account.
	counts := map[string]int{}

	for _, login := range in.Logins {
		for _, name := range in.Generic {
			if strings.EqualFold(login.Account, name) {
				counts[strings.ToLower(login.Account)]++
				break
			}
		}
	}

	if len(counts) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: "generic accounts authenticated: " + countList(counts),
		}
	}

	// 4. The log arrives and no forbidden account logged in.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d sshd logins in the window, none with a P-04 account", len(in.Logins)),
	}
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

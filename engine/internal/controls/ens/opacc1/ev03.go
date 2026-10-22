package opacc1

import (
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
	// TODO(dioni): then remove the t.Skip in ev03_test.go.
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseEvidence, Reason: "EV-03 judgement not implemented"}
}

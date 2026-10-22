package opacc1

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV07Input is what the engine knows about one agent when judging EV-07: the
// EV-01 inventory and the usuario column of P-07.
type EV07Input struct {
	Inventory EV01Input
	// Authorized is the usuario column of P-07. Empty when
	// AuthorizedProblem is set.
	Authorized []string
	// AuthorizedProblem says why P-07 cannot be used; "" when it can.
	AuthorizedProblem string
}

// JudgeEV07 judges EV-07 (every active account is in the authorized list) as
// described in catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. AuthorizedProblem set: NOT_EVALUABLE, CONFIGURATION.
//  2. Inventory unusable: as EV-01 steps 1 to 3.
//  3. Active accounts (login_enabled) not in P-07, compared literally and
//     with case: NON_COMPLIANT, reason lists them.
//  4. Otherwise COMPLIANT.
func JudgeEV07(in EV07Input) verdict.Judgement {

	// 1. Without the list there is nothing to compare against.
	if in.AuthorizedProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, "P-07: "+in.AuthorizedProblem)
	}

	// 2. The same inventory as EV-01, so the same reasons it cannot be used.
	if gap, found := inventoryGap(in.Inventory); found {
		return gap
	}

	// 3. Literal and case-sensitive, as the plugin does: "Jgomez" is not
	// "jgomez" on a Linux system.
	authorized := map[string]bool{}

	for _, name := range in.Authorized {
		authorized[name] = true
	}

	active := 0
	var missing []string

	for _, record := range in.Inventory.Records {

		if !record.LoginEnabled {
			continue
		}

		active++

		if !authorized[record.AccountName] {
			missing = append(missing, record.AccountName)
		}
	}

	if len(missing) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: "active accounts not in P-07: " + strings.Join(missing, ", "),
		}
	}

	// 4. Every active account is authorized.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d active accounts, all in P-07", active),
	}
}

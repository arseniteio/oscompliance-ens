package opacc1

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV07Input is what the engine knows about one agent when judging EV-07: the
// inventory and the usuario column of P-07.
type EV07Input struct {
	Inventory Inventory
	// Authorized is the usuario column of P-07. Empty when
	// AuthorizedProblem is set.
	Authorized []string
	// AuthorizedProblem says why P-07 cannot be used; "" when it can.
	AuthorizedProblem string
}

// JudgeEV07 judges EV-07 (every active account is in the authorized list) as
// described in catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. P-07 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Inventory unusable: as EV-01 steps 1 and 2.
//  3. An active account (UID >= P-10 and not disabled) not in P-07, compared
//     literally and with case: NON_COMPLIANT, reason lists them.
//  4. An account not in P-07 whose disabled state is unknown: NOT_EVALUABLE,
//     EVIDENCE.
//  5. Otherwise COMPLIANT.
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
	var missing, unknown []string

	for _, record := range in.Inventory.people() {

		disabled, known := IsDisabled(record, in.Inventory.Today)

		if disabled {
			continue
		}

		if !known {
			if !authorized[record.AccountName] {
				unknown = append(unknown, record.AccountName)
			}
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

	// 4. Not in the list, and whether it can log in is not known.
	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence,
			"accounts not in P-07 with a locked password and SSH keys unknown: "+strings.Join(unknown, ", "))
	}

	// 5. Every active account is authorized.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d active accounts, all in P-07", active),
	}
}

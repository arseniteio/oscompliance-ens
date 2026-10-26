package opacc1

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV07Input struct {
	Inventory Inventory

	Authorized []string

	AuthorizedProblem string
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if in.AuthorizedProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, "P-07: "+in.AuthorizedProblem)
	}

	if gap, found := inventoryGap(in.Inventory); found {
		return gap
	}

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

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence,
			"accounts not in P-07 with a locked password and SSH keys unknown: "+strings.Join(unknown, ", "))
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d active accounts, all in P-07", active),
	}
}

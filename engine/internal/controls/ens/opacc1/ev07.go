package opacc1

import (
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV07Input struct {
	Inventory Inventory

	Authorized []string

	AuthorizedProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if !in.AuthorizedProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.AuthorizedProblem)
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
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev07.unlisted", "accounts", missing))
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev07.keys_unknown", "accounts", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev07.listed", "accounts", active))
}

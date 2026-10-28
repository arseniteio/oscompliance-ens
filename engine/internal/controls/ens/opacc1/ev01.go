package opacc1

import (
	"sort"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Inventory struct {
	Current *fact.IdentitySnapshot

	Records []fact.IdentityRecord

	UIDMin int

	UIDMinProblem catalog.Message

	Today time.Time
}

func (in Inventory) people() []fact.IdentityRecord {

	var people []fact.IdentityRecord

	for _, record := range in.Records {
		if record.UID >= in.UIDMin {
			people = append(people, record)
		}
	}

	return people
}

func inventoryGap(in Inventory) (verdict.Judgement, bool) {

	if !in.UIDMinProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.UIDMinProblem), true
	}

	return identityGap(in.Current, in.Records)
}

func JudgeEV01(in Inventory) verdict.Judgement {

	if gap, found := inventoryGap(in); found {
		return gap
	}

	byUID := map[int][]string{}

	for _, record := range in.Records {
		byUID[record.UID] = append(byUID[record.UID], record.AccountName)
	}

	var uids []int

	for uid, names := range byUID {
		if len(names) > 1 {
			uids = append(uids, uid)
		}
	}

	sort.Ints(uids)

	var shared []catalog.Message

	for _, uid := range uids {
		shared = append(shared, catalog.Says("opacc1.uid_shared_by", "uid", uid, "accounts", byUID[uid]))
	}

	if len(shared) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev01.shared_uids", "uids", shared))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev01.unique",
		"accounts", len(in.Records), "people", len(in.people()), "uid_min", in.UIDMin))
}

func notEvaluable(cause verdict.Cause, m catalog.Message) verdict.Judgement {
	return passes.Gap(cause, m)
}

package opacc1

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Inventory struct {
	Current *fact.IdentitySnapshot

	Records []fact.IdentityRecord

	UIDMin int

	UIDMinProblem string

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

	if in.UIDMinProblem != "" {
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

	var shared []string

	for _, uid := range uids {
		shared = append(shared, fmt.Sprintf("UID %d (%s)", uid, strings.Join(byUID[uid], ", ")))
	}

	if len(shared) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: "UIDs shared by more than one account: " + strings.Join(shared, "; "),
		}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts, %d with UID >= %d (P-10), all UIDs unique", len(in.Records), len(in.people()), in.UIDMin),
	}
}

func notEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

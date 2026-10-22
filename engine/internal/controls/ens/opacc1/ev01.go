// Package opacc1 judges the evidences of ENS control op.acc.1.
package opacc1

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Inventory is the current identity pass (EV-02 facts) and P-10, which EV-01
// and EV-07 judge.
type Inventory struct {
	// Current is the newest identity_snapshot in the window; nil when none.
	Current *fact.IdentitySnapshot
	// Records are the identity_record facts of Current.RunID.
	Records []fact.IdentityRecord
	// UIDMin is P-10: accounts below it belong to the system.
	UIDMin int
	// UIDMinProblem names an unusable P-10; "" when usable.
	UIDMinProblem string
	// Today is the evaluation day, for expiry dates.
	Today time.Time
}

// people returns the accounts with UID >= UIDMin.
func (in Inventory) people() []fact.IdentityRecord {

	var people []fact.IdentityRecord

	for _, record := range in.Records {
		if record.UID >= in.UIDMin {
			people = append(people, record)
		}
	}

	return people
}

// inventoryGap checks that the inventory can be judged: P-10 usable and the
// identity pass complete. Shared by EV-01 and EV-07.
func inventoryGap(in Inventory) (verdict.Judgement, bool) {

	if in.UIDMinProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.UIDMinProblem), true
	}

	return identityGap(in.Current, in.Records)
}

// JudgeEV01 judges EV-01 (account inventory, unique UIDs) as described in
// catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. P-10 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Identity pass missing, unread or incomplete: as EV-02 steps 1 to 4.
//  3. A UID held by more than one entry, at any UID (as v1): NON_COMPLIANT.
//  4. Otherwise COMPLIANT.
func JudgeEV01(in Inventory) verdict.Judgement {

	// 1 and 2. Without a complete inventory there is nothing to judge.
	if gap, found := inventoryGap(in); found {
		return gap
	}

	// 3. Two or more accounts share a UID.
	byUID := map[int][]string{}

	for _, record := range in.Records {
		byUID[record.UID] = append(byUID[record.UID], record.AccountName)
	}

	// Map order is random; UIDs in order keep reasons comparable.
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

	// 4. Complete inventory, every UID unique.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts, %d with UID >= %d (P-10), all UIDs unique", len(in.Records), len(in.people()), in.UIDMin),
	}
}

func notEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

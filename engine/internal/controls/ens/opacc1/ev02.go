package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV02Input struct {
	Current *fact.IdentitySnapshot

	Records []fact.IdentityRecord

	Previous *fact.IdentitySnapshot

	PreviousRecords []fact.IdentityRecord
}

type IdentityChanges struct {
	Created  []string
	Deleted  []string
	Modified []string
}

func DiffIdentities(previous, current []fact.IdentityRecord) IdentityChanges {

	before := byAccountName(previous)
	after := byAccountName(current)

	var changes IdentityChanges

	for name, record := range after {

		old, existed := before[name]

		if !existed {
			changes.Created = append(changes.Created, name)
		} else if !sameIdentity(old, record) {
			changes.Modified = append(changes.Modified, name)
		}
	}

	for name := range before {
		if _, exists := after[name]; !exists {
			changes.Deleted = append(changes.Deleted, name)
		}
	}

	sort.Strings(changes.Created)
	sort.Strings(changes.Deleted)
	sort.Strings(changes.Modified)

	return changes
}

func sameIdentity(a, b fact.IdentityRecord) bool {
	return a.AccountName == b.AccountName && a.UID == b.UID && a.GID == b.GID &&
		a.Shell == b.Shell && a.PasswordState == b.PasswordState &&
		a.AccountExpires == b.AccountExpires && sameCount(a.AuthorizedKeys, b.AuthorizedKeys)
}

func sameCount(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func byAccountName(records []fact.IdentityRecord) map[string]fact.IdentityRecord {

	index := map[string]fact.IdentityRecord{}

	for _, record := range records {

		if _, seen := index[record.AccountName]; seen {
			continue
		}

		record.Envelope = fact.Envelope{}
		index[record.AccountName] = record
	}

	return index
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if gap, found := identityGap(in.Current, in.Records); found {
		return gap
	}

	received := len(in.Records)

	if in.Previous == nil {
		return verdict.Judgement{
			Status: verdict.Compliant,
			Reason: fmt.Sprintf("baseline: first complete pass, %d accounts", received),
		}
	}

	changes := DiffIdentities(in.PreviousRecords, in.Records)

	var parts []string

	if len(changes.Created) > 0 {
		parts = append(parts, "created: "+strings.Join(changes.Created, ", "))
	}
	if len(changes.Deleted) > 0 {
		parts = append(parts, "deleted: "+strings.Join(changes.Deleted, ", "))
	}
	if len(changes.Modified) > 0 {
		parts = append(parts, "modified: "+strings.Join(changes.Modified, ", "))
	}

	if len(parts) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no changes since " + in.Previous.RunID}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: "since " + in.Previous.RunID + ": " + strings.Join(parts, "; "),
	}
}

func identityGap(current *fact.IdentitySnapshot, records []fact.IdentityRecord) (verdict.Judgement, bool) {
	return passes.IdentityGap(current, records)
}

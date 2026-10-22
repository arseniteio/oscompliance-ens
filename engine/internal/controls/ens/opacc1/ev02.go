package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV02Input is what the engine knows about one agent when judging EV-02.
type EV02Input struct {
	// Current is the newest identity_snapshot in the window; nil when the
	// agent sent none.
	Current *fact.IdentitySnapshot
	// Records are the identity_record facts received with Current.RunID.
	Records []fact.IdentityRecord
	// Previous is the newest complete pass before Current (both files read,
	// every record received); nil when there is none in the lookback.
	Previous *fact.IdentitySnapshot
	// PreviousRecords are the identity_record facts of Previous.
	PreviousRecords []fact.IdentityRecord
}

// IdentityChanges lists account names, each list sorted alphabetically.
type IdentityChanges struct {
	Created  []string
	Deleted  []string
	Modified []string
}

// DiffIdentities compares two passes by account_name. An account is modified
// when uid, gid, shell, password_state, account_expires or authorized_keys
// differ; envelope
// fields (ts, run_id, ...) always differ and do not count. When a name appears
// twice in one pass, the first record wins.
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

	// Map order is random; sorted lists keep reasons comparable between passes.
	sort.Strings(changes.Created)
	sort.Strings(changes.Deleted)
	sort.Strings(changes.Modified)

	return changes
}

// sameIdentity compares the account fields of two records. Not ==: a pointer
// field (AuthorizedKeys) would compare addresses, and every account would
// look modified on every pass.
func sameIdentity(a, b fact.IdentityRecord) bool {
	return a.AccountName == b.AccountName && a.UID == b.UID && a.GID == b.GID &&
		a.Shell == b.Shell && a.PasswordState == b.PasswordState &&
		a.AccountExpires == b.AccountExpires && sameCount(a.AuthorizedKeys, b.AuthorizedKeys)
}

// sameCount compares two optional counts by value; nil means unknown.
func sameCount(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// byAccountName indexes records by name, first record wins. The envelope is
// cleared: two passes always differ in it.
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

// JudgeEV02 judges EV-02 (identity changes are recorded) as described in
// catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. Current nil: NOT_EVALUABLE, COLLECTION.
//  2. passwd or shadow not read: NOT_EVALUABLE, COLLECTION, reason with the error.
//  3. Current read without records_emitted: NOT_EVALUABLE, EVIDENCE.
//  4. Fewer Records than records_emitted: NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT. Reason:
//     - Previous nil: "baseline: first complete pass, N accounts"
//     - no changes: "no changes since <Previous.RunID>"
//     - changes: "since <Previous.RunID>: created: a, b; deleted: c; modified: d"
//     (only the non-empty lists, in that order)
func JudgeEV02(in EV02Input) verdict.Judgement {

	// 1 to 4. The current pass must be complete.
	if gap, found := identityGap(in.Current, in.Records); found {
		return gap
	}

	received := len(in.Records)

	// 5. Changes are being recorded. The reason says which.
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

// identityGap checks that an identity pass can be used at all: steps 1 to 4
// of EV-02, shared with EV-01 and EV-07, which judge the same table. found is
// true when it cannot; the judgement says why.
func identityGap(current *fact.IdentitySnapshot, records []fact.IdentityRecord) (gap verdict.Judgement, found bool) {

	// 1. Nothing to judge.
	if current == nil {
		return notEvaluable(verdict.CauseCollection, "no identity_snapshot in the window"), true
	}

	// 2. The agent could not read the identity files.
	if current.PasswdStatus != fact.SourceRead {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", current.PasswdPath, current.PasswdStatus, current.PasswdError)), true
	}

	if current.ShadowStatus != fact.SourceRead {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", current.ShadowPath, current.ShadowStatus, current.ShadowError)), true
	}

	// 3. A complete read always carries the counter (schema). Without it the
	// fact is broken, not missing, hence EVIDENCE and not COLLECTION.
	if current.RecordsEmitted == nil {
		return notEvaluable(verdict.CauseEvidence, "read snapshot without records_emitted"), true
	}

	// 4. Records lost on the way. More than announced is fine: Wazuh can
	// deliver a line twice.
	if len(records) < *current.RecordsEmitted {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d identity_record received", current.RunID, len(records), *current.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

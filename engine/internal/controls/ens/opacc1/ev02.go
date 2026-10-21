package opacc1

import (
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
// when uid, gid, shell, password_state or account_expires differ; envelope
// fields (ts, run_id, ...) always differ and do not count. When a name appears
// twice in one pass, the first record wins.
func DiffIdentities(previous, current []fact.IdentityRecord) IdentityChanges {
	// TODO(dioni)
	return IdentityChanges{}
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
	// TODO(dioni): then remove the t.Skip lines in ev02_test.go.
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseEvidence, Reason: "EV-02 judgement not implemented"}
}

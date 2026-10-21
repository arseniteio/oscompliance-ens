// Package opacc1 judges the evidences of ENS control op.acc.1.
package opacc1

import (
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV01Input is what the engine knows about one agent when judging EV-01.
type EV01Input struct {
	// Snapshot is the newest account_inventory_snapshot in the window; nil
	// when the agent sent none.
	Snapshot *fact.AccountInventorySnapshot
	// Records are the account_record facts received with Snapshot.RunID.
	// Empty when Snapshot is nil or was not read.
	Records []fact.AccountRecord
}

// JudgeEV01 judges EV-01 (account inventory, unique UIDs) as described in
// catalog/docs/contracts/op.acc.1.md, section 7.
func JudgeEV01(in EV01Input) verdict.Judgement {
	// TODO(dioni): section 7, then remove the t.Skip in ev01_test.go.
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: verdict.CauseEvidence, Reason: "EV-01 judgement not implemented"}
}

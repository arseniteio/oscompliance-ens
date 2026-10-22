// Package opacc1 judges the evidences of ENS control op.acc.1.
package opacc1

import (
	"fmt"
	"strings"

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
// The steps are checked in order and the first one that applies decides.
func JudgeEV01(in EV01Input) verdict.Judgement {

	// 1 to 3. Without a complete inventory there is nothing to judge.
	if gap, found := inventoryGap(in); found {
		return gap
	}

	snapshot := in.Snapshot

	// 4. Two or more accounts share a UID.
	if len(snapshot.DuplicateUIDs) > 0 {

		var shared []string

		for _, dup := range snapshot.DuplicateUIDs {
			shared = append(shared, fmt.Sprintf("UID %d (%s)", dup.UID, strings.Join(dup.AccountNames, ", ")))
		}

		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: "UIDs shared by more than one account: " + strings.Join(shared, "; "),
		}
	}

	// 5. Complete inventory, every UID unique.
	return verdict.Judgement{Status: verdict.Compliant}
}

// inventoryGap checks that the account inventory can be used at all: steps 1
// to 3 of EV-01, shared with EV-07, which judges the same inventory. found is
// true when the inventory cannot be used; the judgement says why.
func inventoryGap(in EV01Input) (gap verdict.Judgement, found bool) {

	snapshot := in.Snapshot

	// 1. Nothing to judge: the agent did not report a pass in the window.
	if snapshot == nil {
		return notEvaluable(verdict.CauseCollection, "no account_inventory_snapshot in the window"), true
	}

	// 2. The agent ran but could not trust what it read.
	if snapshot.SourceStatus != fact.SourceRead {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", snapshot.SourcePath, snapshot.SourceStatus, snapshot.SourceError)), true
	}

	// A read snapshot always carries the counters (schema). Without them the
	// fact is broken, not missing, hence EVIDENCE and not COLLECTION.
	if snapshot.RecordsEmitted == nil {
		return notEvaluable(verdict.CauseEvidence, "read snapshot without records_emitted"), true
	}

	// 3. Some records of the pass were lost on the way. More than announced is
	// fine: Wazuh can deliver a line twice.
	received := len(in.Records)
	emitted := *snapshot.RecordsEmitted

	if received < emitted {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d account_record received", snapshot.RunID, received, emitted)), true
	}

	return verdict.Judgement{}, false
}

func notEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

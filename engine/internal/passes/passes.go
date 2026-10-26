// Package passes checks that a pass of facts can be used: present in the
// window, its sources read, and every announced record received. Every
// control that reads the same facts gives the same reasons.
package passes

import (
	"fmt"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// NotEvaluable builds a NOT_EVALUABLE judgement.
func NotEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

// IdentityGap: the identity pass (passwd + shadow) cannot be used. found is
// true when it cannot; the judgement says why.
func IdentityGap(current *fact.IdentitySnapshot, records []fact.IdentityRecord) (gap verdict.Judgement, found bool) {

	if current == nil {
		return NotEvaluable(verdict.CauseCollection, "no identity_snapshot in the window"), true
	}

	if current.PasswdStatus != fact.SourceRead {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", current.PasswdPath, current.PasswdStatus, current.PasswdError)), true
	}

	if current.ShadowStatus != fact.SourceRead {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", current.ShadowPath, current.ShadowStatus, current.ShadowError)), true
	}

	// A complete read always carries the counter (schema). Without it the
	// fact is broken, not missing, hence EVIDENCE and not COLLECTION.
	if current.RecordsEmitted == nil {
		return NotEvaluable(verdict.CauseEvidence, "read snapshot without records_emitted"), true
	}

	// More than announced is fine: Wazuh can deliver a line twice.
	if len(records) < *current.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d identity_record received", current.RunID, len(records), *current.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

// GroupGap: the group pass cannot be used.
func GroupGap(groups *fact.GroupSnapshot, records []fact.GroupRecord) (gap verdict.Judgement, found bool) {

	if groups == nil {
		return NotEvaluable(verdict.CauseCollection, "no group_snapshot in the window"), true
	}

	if groups.GroupStatus != fact.SourceRead {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", groups.GroupPath, groups.GroupStatus, groups.GroupError)), true
	}

	if groups.RecordsEmitted == nil {
		return NotEvaluable(verdict.CauseEvidence, "read group_snapshot without records_emitted"), true
	}

	if len(records) < *groups.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d group_record received", groups.RunID, len(records), *groups.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

// SweepGap: the filesystem sweep cannot be used at all (missing, or it
// could not start). A timed-out, cut or partly unreadable sweep is still
// usable for what it found; Partial says whether silence can be trusted.
func SweepGap(sweep *fact.FileSweepSnapshot, records []fact.SpecialFile) (gap verdict.Judgement, found bool) {

	if sweep == nil {
		return NotEvaluable(verdict.CauseCollection, "no file_sweep_snapshot in the window"), true
	}

	if sweep.Status == fact.SweepError {
		return NotEvaluable(verdict.CauseCollection, "sweep failed: "+sweep.SweepError), true
	}

	if len(records) < sweep.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("sweep %s incomplete: %d of %d special_file received", sweep.RunID, len(records), sweep.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

// Partial says why a usable sweep does not cover everything ("" when it does):
// findings stand, but "nothing found" cannot be asserted.
func Partial(sweep fact.FileSweepSnapshot) string {

	switch {
	case sweep.Status == fact.SweepTimeout:
		return "the sweep hit its time limit"
	case sweep.Status == fact.SweepTruncated:
		return "the sweep found more special files than it reports"
	case sweep.Unreadable > 0:
		return fmt.Sprintf("%d directories could not be read", sweep.Unreadable)
	}

	return ""
}

// ConfigGap: the configuration read cannot be used. One unreadable source is
// not a gap of the whole read: each judge asks for the sources it needs.
func ConfigGap(snapshot *fact.ConfigSnapshot, records []fact.ConfigFile) (gap verdict.Judgement, found bool) {

	if snapshot == nil {
		return NotEvaluable(verdict.CauseCollection, "no config_snapshot in the window"), true
	}

	if len(records) < snapshot.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("configuration read %s incomplete: %d of %d config_file received", snapshot.RunID, len(records), snapshot.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

// PAMGap: the PAM read cannot be used. A missing /etc/pam.d is not a gap:
// nothing authenticates through PAM, and the judge decides what that means.
func PAMGap(snapshot *fact.PAMSnapshot, records []fact.PAMRule) (gap verdict.Judgement, found bool) {

	if snapshot == nil {
		return NotEvaluable(verdict.CauseCollection, "no pam_snapshot in the window"), true
	}

	if snapshot.Status == fact.SourceUnreadable {
		return NotEvaluable(verdict.CauseCollection, "PAM configuration unreadable: "+snapshot.Error), true
	}

	if len(records) < snapshot.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("PAM read %s incomplete: %d of %d pam_rule received", snapshot.RunID, len(records), snapshot.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

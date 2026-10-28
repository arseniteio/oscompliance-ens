package passes

import (
	"fmt"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func NotEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

func Gap(cause verdict.Cause, m catalog.Message) verdict.Judgement {
	return verdict.Explain(verdict.NotEvaluable, cause, m)
}

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

	if current.RecordsEmitted == nil {
		return NotEvaluable(verdict.CauseEvidence, "read snapshot without records_emitted"), true
	}

	if len(records) < *current.RecordsEmitted {
		return NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d identity_record received", current.RunID, len(records), *current.RecordsEmitted)), true
	}

	return verdict.Judgement{}, false
}

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

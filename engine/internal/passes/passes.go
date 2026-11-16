package passes

import (
	"errors"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func Gap(cause verdict.Cause, m catalog.Message) verdict.Judgement {
	return verdict.Explain(verdict.NotEvaluable, cause, m)
}

func Source(path, status, err string) catalog.Message {
	return catalog.Says("gap.source", "path", path, "status", catalog.Says("source."+status), "error", err)
}

func Incomplete(run string, got, want int, fact string) catalog.Message {
	return catalog.Says("gap.incomplete", "run", run, "got", got, "want", want, "fact", fact)
}

func Problems(list []catalog.Message) catalog.Message {
	if len(list) == 0 {
		return catalog.Message{}
	}
	return catalog.Says("findings_semicolon", "list", list)
}

func Param(id string, err error) catalog.Message {
	if errors.Is(err, params.ErrNotSet) {
		return catalog.Says("param.not_set", "param", id)
	}
	if v, ok := errors.AsType[params.ValueError](err); ok {
		return catalog.Says("param.invalid", "param", id, "error", v.Message)
	}
	return catalog.Says("param.invalid", "param", id, "error", err.Error())
}

func ParamProblem(id string, err error) catalog.Message {
	if err != nil {
		return Param(id, err)
	}
	return catalog.Message{}
}

func Whole(policy params.Lister, agentID, control, id, notWhole string) (int, catalog.Message) {
	v, err := policy.Number(agentID, control, id)
	if err != nil {
		return 0, Param(id, err)
	}
	if v < 1 || v != float64(int(v)) {
		return 0, catalog.Says(notWhole, "param", id, "value", v)
	}
	return int(v), catalog.Message{}
}

func Cells(row string, n int) []string {
	c := strings.Split(row, "|")
	for len(c) < n {
		c = append(c, "")
	}
	for i := range c {
		c[i] = strings.TrimSpace(c[i])
	}
	return c
}

func IdentityGap(current *fact.IdentitySnapshot, records []fact.IdentityRecord) (gap verdict.Judgement, found bool) {

	if current == nil {
		return Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", "identity_snapshot")), true
	}

	if current.PasswdStatus != fact.SourceRead {
		return Gap(verdict.CauseCollection, Source(current.PasswdPath, current.PasswdStatus, current.PasswdError)), true
	}

	if current.ShadowStatus != fact.SourceRead {
		return Gap(verdict.CauseCollection, Source(current.ShadowPath, current.ShadowStatus, current.ShadowError)), true
	}

	if current.RecordsEmitted == nil {
		return Gap(verdict.CauseEvidence, catalog.Says("gap.no_records_emitted", "fact", "identity_snapshot")), true
	}

	if len(records) < *current.RecordsEmitted {
		return Gap(verdict.CauseCollection, Incomplete(current.RunID, len(records), *current.RecordsEmitted, "identity_record")), true
	}

	return verdict.Judgement{}, false
}

func GroupGap(groups *fact.GroupSnapshot, records []fact.GroupRecord) (gap verdict.Judgement, found bool) {

	if groups == nil {
		return Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", "group_snapshot")), true
	}

	if groups.GroupStatus != fact.SourceRead {
		return Gap(verdict.CauseCollection, Source(groups.GroupPath, groups.GroupStatus, groups.GroupError)), true
	}

	if groups.RecordsEmitted == nil {
		return Gap(verdict.CauseEvidence, catalog.Says("gap.no_records_emitted", "fact", "group_snapshot")), true
	}

	if len(records) < *groups.RecordsEmitted {
		return Gap(verdict.CauseCollection, Incomplete(groups.RunID, len(records), *groups.RecordsEmitted, "group_record")), true
	}

	return verdict.Judgement{}, false
}

func SweepGap(sweep *fact.FileSweepSnapshot, records []fact.SpecialFile) (gap verdict.Judgement, found bool) {

	if sweep == nil {
		return Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", "file_sweep_snapshot")), true
	}

	if sweep.Status == fact.SweepError {
		return Gap(verdict.CauseCollection, catalog.Says("gap.sweep_failed", "error", sweep.SweepError)), true
	}

	if len(records) < sweep.RecordsEmitted {
		return Gap(verdict.CauseCollection, Incomplete(sweep.RunID, len(records), sweep.RecordsEmitted, "special_file")), true
	}

	return verdict.Judgement{}, false
}

func Partial(sweep fact.FileSweepSnapshot) catalog.Message {

	switch {
	case sweep.Status == fact.SweepTimeout:
		return catalog.Says("gap.sweep_timeout")
	case sweep.Status == fact.SweepTruncated:
		return catalog.Says("gap.sweep_truncated")
	case sweep.Unreadable > 0:
		return catalog.Says("gap.sweep_unreadable", "count", sweep.Unreadable)
	}

	return catalog.Message{}
}

func ConfigGap(snapshot *fact.ConfigSnapshot, records []fact.ConfigFile) (gap verdict.Judgement, found bool) {

	if snapshot == nil {
		return Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", "config_snapshot")), true
	}

	if len(records) < snapshot.RecordsEmitted {
		return Gap(verdict.CauseCollection, Incomplete(snapshot.RunID, len(records), snapshot.RecordsEmitted, "config_file")), true
	}

	return verdict.Judgement{}, false
}

func PAMGap(snapshot *fact.PAMSnapshot, records []fact.PAMRule) (gap verdict.Judgement, found bool) {

	if snapshot == nil {
		return Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", "pam_snapshot")), true
	}

	if snapshot.Status == fact.SourceUnreadable {
		return Gap(verdict.CauseCollection, catalog.Says("gap.pam_unreadable", "error", snapshot.Error)), true
	}

	if len(records) < snapshot.RecordsEmitted {
		return Gap(verdict.CauseCollection, Incomplete(snapshot.RunID, len(records), snapshot.RecordsEmitted, "pam_rule")), true
	}

	return verdict.Judgement{}, false
}

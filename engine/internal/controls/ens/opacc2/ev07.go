package opacc2

import (
	"path/filepath"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type EV07Input struct {
	Sweep Sweep

	Authorized        []string
	AuthorizedProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}

	authorized := map[string]bool{}
	for _, p := range in.Authorized {
		authorized[filepath.Clean(p)] = true
	}

	var unowned, unauthorized []catalog.Message
	privileged := 0

	for _, f := range in.Sweep.Files {

		if f.NoOwner || f.NoGroup {
			unowned = append(unowned, catalog.Says("opacc2.unowned_file", "path", f.Path, "uid", f.UID, "gid", f.GID))
		}

		if f.SUID || f.SGID {
			privileged++
			if in.AuthorizedProblem.IsZero() && !authorized[f.Path] {
				unauthorized = append(unauthorized, catalog.Says("item.path_mode", "path", f.Path, "mode", f.Mode))
			}
		}
	}

	var findings []catalog.Message

	if len(unowned) > 0 {
		catalog.SortMessages(unowned)
		findings = append(findings, catalog.Says("opacc2.without_owner", "files", unowned))
	}

	if len(unauthorized) > 0 {
		catalog.SortMessages(unauthorized)
		findings = append(findings, catalog.Says("opacc2.suid_not_in_p10", "files", unauthorized))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
	}

	if privileged > 0 && !in.AuthorizedProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.a_suid_sgid_files_and_p_10_cannot_be_use", "a", privileged, "b", in.AuthorizedProblem))
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); !partial.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.nothing_found_but_a", "a", partial))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_suid_sgid_files_all_in_p_10_no_file_wi", "a", privileged))
}

package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV07Input struct {
	Sweep Sweep

	Authorized        []string
	AuthorizedProblem string
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}

	authorized := map[string]bool{}
	for _, p := range in.Authorized {
		authorized[filepath.Clean(p)] = true
	}

	var unowned, unauthorized []string
	privileged := 0

	for _, f := range in.Sweep.Files {

		if f.NoOwner || f.NoGroup {
			unowned = append(unowned, fmt.Sprintf("%s (uid %d, gid %d)", f.Path, f.UID, f.GID))
		}

		if f.SUID || f.SGID {
			privileged++
			if in.AuthorizedProblem == "" && !authorized[f.Path] {
				unauthorized = append(unauthorized, fmt.Sprintf("%s (%s)", f.Path, f.Mode))
			}
		}
	}

	var findings []string

	if len(unowned) > 0 {
		sort.Strings(unowned)
		findings = append(findings, "without owner or group: "+strings.Join(unowned, ", "))
	}

	if len(unauthorized) > 0 {
		sort.Strings(unauthorized)
		findings = append(findings, "SUID/SGID not in P-10: "+strings.Join(unauthorized, ", "))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.a", "a", findings))
	}

	if privileged > 0 && in.AuthorizedProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.a_suid_sgid_files_and_p_10_cannot_be_use", "a", privileged, "b", in.AuthorizedProblem))
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); !partial.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.nothing_found_but_a", "a", partial))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_suid_sgid_files_all_in_p_10_no_file_wi", "a", privileged))
}

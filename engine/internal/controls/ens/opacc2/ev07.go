package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV07Input is what EV-07 (access control weaknesses in the OS) needs.
type EV07Input struct {
	Sweep Sweep

	// Authorized is P-10, the SUID/SGID baseline (exact paths).
	// AuthorizedProblem says why it cannot be used; ErrNotSet is reported as
	// "not set" and only matters when a SUID/SGID file exists.
	Authorized        []string
	AuthorizedProblem string
}

// JudgeEV07 judges EV-07 as described in catalog/docs/contracts/op.acc.2.md:
//
//  1. Sweep missing or failed: NOT_EVALUABLE, COLLECTION.
//  2. A file or directory without owner or group: NON_COMPLIANT, with or
//     without P-10.
//  3. A SUID or SGID file not in P-10: NON_COMPLIANT. With SUID/SGID files and
//     P-10 unusable: NOT_EVALUABLE, CONFIGURATION, unless step 2 failed.
//  4. Nothing found but the sweep is partial: NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT.
func JudgeEV07(in EV07Input) verdict.Judgement {

	// 1. Nothing to judge.
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

	// 2. No owner: nobody answers for the file, whatever the baseline says.
	if len(unowned) > 0 {
		sort.Strings(unowned)
		findings = append(findings, "without owner or group: "+strings.Join(unowned, ", "))
	}

	// 3. SUID/SGID nobody reviewed.
	if len(unauthorized) > 0 {
		sort.Strings(unauthorized)
		findings = append(findings, "SUID/SGID not in P-10: "+strings.Join(unauthorized, ", "))
	}

	if len(findings) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(findings, ". ")}
	}

	if privileged > 0 && in.AuthorizedProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration,
			fmt.Sprintf("%d SUID/SGID files and P-10 cannot be used: %s", privileged, in.AuthorizedProblem))
	}

	// 4. Silence only counts when the sweep saw everything.
	if partial := passes.Partial(*in.Sweep.Snapshot); partial != "" {
		return passes.NotEvaluable(verdict.CauseCollection, "nothing found, but "+partial)
	}

	// 5. Every SUID/SGID reviewed, every file owned.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d SUID/SGID files, all in P-10; no file without owner", privileged),
	}
}

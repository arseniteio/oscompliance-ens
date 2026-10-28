package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Sweep struct {
	Snapshot *fact.FileSweepSnapshot
	Files    []fact.SpecialFile
}

type EV01Input struct {
	Sweep Sweep
	Umask *fact.UmaskSnapshot

	Scope         []string
	Exceptions    []string
	StickyAllowed bool
	MinUmask      string

	ConfigProblem string
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if in.ConfigProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.a", "a", in.ConfigProblem))
	}

	minimum, err := strconv.ParseUint(in.MinUmask, 8, 32)
	if err != nil || len(in.MinUmask) > 4 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.p_07_a_is_not_an_octal_umask", "a", in.MinUmask))
	}

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}
	if in.Umask == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_umask_snapshot_in_the_window"))
	}

	exception := map[string]bool{}
	for _, p := range in.Exceptions {
		exception[filepath.Clean(p)] = true
	}

	var writable []string

	for _, f := range in.Sweep.Files {

		if !f.WorldWritable || !underAny(f.Path, in.Scope) || exception[f.Path] {
			continue
		}

		if in.StickyAllowed && f.Kind == "directory" && f.Sticky {
			continue
		}

		writable = append(writable, fmt.Sprintf("%s (%s)", f.Path, f.Mode))
	}

	var weak, blind []string
	declared := 0

	for _, src := range in.Umask.Sources {

		switch src.Status {
		case fact.SourceAbsent:
			continue
		case fact.SourceUnreadable:
			blind = append(blind, src.Path+" unreadable")
			continue
		}

		for _, u := range src.Uninterpretable {
			blind = append(blind, fmt.Sprintf("%s: umask %q is not octal", src.Path, u))
		}

		for _, u := range src.Umasks {
			declared++
			value, _ := strconv.ParseUint(u, 8, 32)
			if value&minimum != minimum {
				weak = append(weak, fmt.Sprintf("%s umask %s", src.Path, u))
			}
		}
	}

	var findings []string

	if len(writable) > 0 {
		sort.Strings(writable)
		findings = append(findings, "world-writable in P-02: "+strings.Join(writable, ", "))
	}
	if len(weak) > 0 {
		findings = append(findings, fmt.Sprintf("umask weaker than %s (P-07): %s", in.MinUmask, strings.Join(weak, ", ")))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.a", "a", findings))
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); !partial.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_world_writable_found_but_a", "a", partial))
	}
	if len(blind) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.umask_cannot_be_known_a", "a", blind))
	}
	if declared == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_source_declares_a_umask"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.no_world_writable_in_a_p_02_paths_b_umas", "a", len(in.Scope), "b", declared, "c", in.MinUmask))
}

func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

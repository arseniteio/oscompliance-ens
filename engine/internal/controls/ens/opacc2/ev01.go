package opacc2

import (
	"path/filepath"
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

	ConfigProblem catalog.Message
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ConfigProblem)
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

	var writable []catalog.Message

	for _, f := range in.Sweep.Files {

		if !f.WorldWritable || !underAny(f.Path, in.Scope) || exception[f.Path] {
			continue
		}

		if in.StickyAllowed && f.Kind == "directory" && f.Sticky {
			continue
		}

		writable = append(writable, catalog.Says("item.path_mode", "path", f.Path, "mode", f.Mode))
	}

	var weak, blind []catalog.Message
	declared := 0

	for _, src := range in.Umask.Sources {

		switch src.Status {
		case fact.SourceAbsent:
			continue
		case fact.SourceUnreadable:
			blind = append(blind, catalog.Says("item.unreadable", "path", src.Path))
			continue
		}

		for _, u := range src.Uninterpretable {
			blind = append(blind, catalog.Says("opacc2.umask_not_octal", "path", src.Path, "umask", u))
		}

		for _, u := range src.Umasks {
			declared++
			value, _ := strconv.ParseUint(u, 8, 32)
			if value&minimum != minimum {
				weak = append(weak, catalog.Says("opacc2.umask_of", "path", src.Path, "umask", u))
			}
		}
	}

	var findings []catalog.Message

	if len(writable) > 0 {
		catalog.SortMessages(writable)
		findings = append(findings, catalog.Says("opacc2.world_writable", "files", writable))
	}
	if len(weak) > 0 {
		findings = append(findings, catalog.Says("opacc2.weak_umask", "minimum", in.MinUmask, "sources", weak))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
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

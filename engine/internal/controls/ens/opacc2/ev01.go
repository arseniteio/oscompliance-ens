package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

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
		return passes.NotEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	minimum, err := strconv.ParseUint(in.MinUmask, 8, 32)
	if err != nil || len(in.MinUmask) > 4 {
		return passes.NotEvaluable(verdict.CauseConfiguration, fmt.Sprintf("P-07: %q is not an octal umask", in.MinUmask))
	}

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}
	if in.Umask == nil {
		return passes.NotEvaluable(verdict.CauseCollection, "no umask_snapshot in the window")
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(findings, ". ")}
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); partial != "" {
		return passes.NotEvaluable(verdict.CauseCollection, "no world-writable found, but "+partial)
	}
	if len(blind) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "umask cannot be known: "+strings.Join(blind, "; "))
	}
	if declared == 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no source declares a umask")
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("no world-writable in %d P-02 paths; %d umask declarations cover %s", len(in.Scope), declared, in.MinUmask),
	}
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

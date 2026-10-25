// Package opacc2 judges the evidences of ENS control op.acc.2.
package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Sweep is the newest filesystem sweep and its special files.
type Sweep struct {
	Snapshot *fact.FileSweepSnapshot
	Files    []fact.SpecialFile
}

// EV01Input is what EV-01 (resources protected by access control) needs.
type EV01Input struct {
	Sweep Sweep
	Umask *fact.UmaskSnapshot

	// Scope is P-02 (critical paths); Exceptions P-11 (world-writable paths
	// allowed by name); StickyAllowed P-03 (a world-writable directory with
	// the sticky bit is accepted); MinUmask P-07 (octal).
	Scope         []string
	Exceptions    []string
	StickyAllowed bool
	MinUmask      string

	// ConfigProblem names an unusable P-02, P-03, P-07 or P-11.
	ConfigProblem string
}

// JudgeEV01 judges EV-01 as described in catalog/docs/contracts/op.acc.2.md:
//
//  1. Parameters unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Sweep or umask facts missing: NOT_EVALUABLE, COLLECTION.
//  3. A world-writable file or directory under a P-02 path that is not a P-11
//     exception (nor, with P-03, a sticky directory), or a declared umask
//     that does not cover every bit of P-07: NON_COMPLIANT.
//  4. Nothing found but the sweep is partial, a umask source is unreadable or
//     a declaration is not octal, or no source declares a umask:
//     NOT_EVALUABLE, COLLECTION. The umask is never assumed.
//  5. Otherwise COMPLIANT.
func JudgeEV01(in EV01Input) verdict.Judgement {

	// 1. Without scope or minimum there is nothing to compare against.
	if in.ConfigProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	minimum, err := strconv.ParseUint(in.MinUmask, 8, 32)
	if err != nil || len(in.MinUmask) > 4 {
		return passes.NotEvaluable(verdict.CauseConfiguration, fmt.Sprintf("P-07: %q is not an octal umask", in.MinUmask))
	}

	// 2. Both sources of facts must be there.
	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}
	if in.Umask == nil {
		return passes.NotEvaluable(verdict.CauseCollection, "no umask_snapshot in the window")
	}

	// 3a. World-writable inside the scope.
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

	// 3b. Every declared umask must mask at least the bits of P-07: 032 does
	// not cover 027 even though it is a larger number.
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

	// 4. Silence only counts when everything was seen.
	if partial := passes.Partial(*in.Sweep.Snapshot); partial != "" {
		return passes.NotEvaluable(verdict.CauseCollection, "no world-writable found, but "+partial)
	}
	if len(blind) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "umask cannot be known: "+strings.Join(blind, "; "))
	}
	if declared == 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no source declares a umask")
	}

	// 5. Nothing writable by everyone in scope, every umask strong enough.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("no world-writable in %d P-02 paths; %d umask declarations cover %s", len(in.Scope), declared, in.MinUmask),
	}
}

// underAny: path is one of dirs or inside one of them.
func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

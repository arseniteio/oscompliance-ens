package opacc2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Accounts struct {
	Identity        *fact.IdentitySnapshot
	IdentityRecords []fact.IdentityRecord
	Groups          *fact.GroupSnapshot
	GroupRecords    []fact.GroupRecord
}

type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

type EV05Input struct {
	Accounts Accounts
	Sudoers  Sudoers

	Groups   []string
	Declared []string

	ConfigProblem string
}

func JudgeEV05(in EV05Input) verdict.Judgement {

	if in.ConfigProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if gap, found := passes.IdentityGap(in.Accounts.Identity, in.Accounts.IdentityRecords); found {
		return gap
	}
	if gap, found := passes.GroupGap(in.Accounts.Groups, in.Accounts.GroupRecords); found {
		return gap
	}

	sudoers := in.Sudoers.Snapshot

	switch {
	case sudoers == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no sudoers_snapshot in the window")
	case sudoers.Status == fact.SourceUnreadable:
		return passes.NotEvaluable(verdict.CauseCollection, "sudoers unreadable")
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("sudoers read %s incomplete: %d of %d sudo_grant received", sudoers.RunID, len(in.Sudoers.Grants), sudoers.RecordsEmitted))
	}

	privileged, unresolved := privilegedAccounts(indexAccounts(in.Accounts), in.Groups, in.Sudoers.Grants)

	declared := map[string]bool{}
	for _, name := range in.Declared {
		declared[name] = true
	}

	var undeclared []string
	for name, via := range privileged {
		if !declared[name] {
			undeclared = append(undeclared, fmt.Sprintf("%s (%s)", name, strings.Join(via, ", ")))
		}
	}

	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "privileges not declared in P-09: " + strings.Join(undeclared, "; ")}
	}

	if sudoers.BlindSpots > 0 {
		return passes.NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("sudoers has %d grants not attributable to named accounts: %s", sudoers.BlindSpots, strings.Join(sudoers.BlindSpotReasons, "; ")))
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		return passes.NotEvaluable(verdict.CauseCollection, "sudoers names groups or uids that do not exist: "+strings.Join(unresolved, ", "))
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d privileged accounts, all declared in P-09", len(privileged)),
	}
}

type accountIndex struct {
	byUID      map[int]string
	groupGID   map[string]int
	groupByGID map[int]string
	secondary  map[string][]string
	primary    map[int][]string
}

func indexAccounts(a Accounts) accountIndex {

	idx := accountIndex{byUID: map[int]string{}, groupGID: map[string]int{}, groupByGID: map[int]string{}, secondary: map[string][]string{}, primary: map[int][]string{}}

	for _, r := range a.IdentityRecords {
		if _, seen := idx.byUID[r.UID]; !seen {
			idx.byUID[r.UID] = r.AccountName
		}
		idx.primary[r.GID] = append(idx.primary[r.GID], r.AccountName)
	}

	for _, g := range a.GroupRecords {
		if _, seen := idx.groupGID[g.GroupName]; seen {
			continue
		}
		idx.groupGID[g.GroupName] = g.GID
		if _, seen := idx.groupByGID[g.GID]; !seen {
			idx.groupByGID[g.GID] = g.GroupName
		}
		idx.secondary[g.GroupName] = g.Members
	}

	return idx
}

func (idx accountIndex) members(group string) []string {

	seen := map[string]bool{}
	var out []string

	for _, name := range idx.secondary[group] {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}

	if gid, ok := idx.groupGID[group]; ok {
		for _, name := range idx.primary[gid] {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}

	return out
}

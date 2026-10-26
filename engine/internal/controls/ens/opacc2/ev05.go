package opacc2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// Accounts is the identity and group passes: who exists and who belongs to
// which group, primary groups included.
type Accounts struct {
	Identity        *fact.IdentitySnapshot
	IdentityRecords []fact.IdentityRecord
	Groups          *fact.GroupSnapshot
	GroupRecords    []fact.GroupRecord
}

// Sudoers is the newest sudoers read and its grants.
type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

// EV05Input is what EV-05 (individual privileges, R1) needs.
type EV05Input struct {
	Accounts Accounts
	Sudoers  Sudoers

	// Groups is P-12 (groups that grant administration); Declared the
	// usuario column of P-09 (accounts whose privileges are declared).
	Groups   []string
	Declared []string

	// ConfigProblem names an unusable P-05, P-09 or P-12.
	ConfigProblem string
}

// JudgeEV05 judges EV-05 as described in catalog/docs/contracts/op.acc.2.md:
//
//  1. P-05 (privilege model), P-09 or P-12 unusable: NOT_EVALUABLE,
//     CONFIGURATION.
//  2. Identity, group or sudoers facts missing: NOT_EVALUABLE, COLLECTION.
//  3. An account with privilege (member of a P-12 group, primary group
//     included, or granted by sudoers; root by sudoers does not count, as v1)
//     not in P-09: NON_COMPLIANT.
//  4. Nothing found but sudoers has blind spots or a grant names a group or
//     uid that does not exist: NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT.
func JudgeEV05(in EV05Input) verdict.Judgement {

	// 1. Without the model and the declarations there is nothing to judge.
	if in.ConfigProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	// 2. Who exists, who belongs where, who has sudo.
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

	// 3. Everyone with privilege, and where it comes from.
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

	// 4. Silence only counts when every grant could be attributed.
	if sudoers.BlindSpots > 0 {
		return passes.NotEvaluable(verdict.CauseCollection,
			fmt.Sprintf("sudoers has %d grants not attributable to named accounts: %s", sudoers.BlindSpots, strings.Join(sudoers.BlindSpotReasons, "; ")))
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		return passes.NotEvaluable(verdict.CauseCollection, "sudoers names groups or uids that do not exist: "+strings.Join(unresolved, ", "))
	}

	// 5. Every privileged account declared.
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
	primary    map[int][]string // accounts by primary gid
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

// members of a group: listed in the group file, or with it as primary group.
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

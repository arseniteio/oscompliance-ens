package opacc2

import (
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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

	ConfigProblem catalog.Message
}

func JudgeEV05(in EV05Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ConfigProblem)
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
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_sudoers_snapshot_in_the_window"))
	case sudoers.Status == fact.SourceUnreadable:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_unreadable"))
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_read_a_incomplete_b_of_c_sudo_gr", "a", sudoers.RunID, "b", len(in.Sudoers.Grants), "c", sudoers.RecordsEmitted))
	}

	privileged, unresolved := privilegedAccounts(indexAccounts(in.Accounts), in.Groups, in.Sudoers.Grants)

	declared := map[string]bool{}
	for _, name := range in.Declared {
		declared[name] = true
	}

	var undeclared []catalog.Message
	for name, via := range privileged {
		if !declared[name] {
			undeclared = append(undeclared, catalog.Says("item.name_list", "name", name, "list", via))
		}
	}

	if len(undeclared) > 0 {
		catalog.SortMessages(undeclared)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.privileges_not_declared_in_p_09_a", "a", undeclared))
	}

	if sudoers.BlindSpots > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_has_a_grants_not_attributable_to", "a", sudoers.BlindSpots, "b", strings.Join(sudoers.BlindSpotReasons, "; ")))
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_names_groups_or_uids_that_do_not", "a", unresolved))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_privileged_accounts_all_declared_in_p", "a", len(privileged)))
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

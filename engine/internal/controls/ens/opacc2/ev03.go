package opacc2

import (
	"fmt"
	"sort"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV03Input struct {
	Accounts Accounts
	Sudoers  Sudoers

	Elevations []source.Elevation
	Log        passes.AuthLog

	Groups []string
}

func JudgeEV03(in EV03Input) verdict.Judgement {

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
	case sudoers.Status == "unreadable":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_unreadable"))
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_read_incomplete_a_of_b_sudo_gran", "a", len(in.Sudoers.Grants), "b", sudoers.RecordsEmitted))
	}

	idx := indexAccounts(in.Accounts)
	privileged, _ := privilegedAccounts(idx, in.Groups, in.Sudoers.Grants)

	local := map[string]bool{}
	for _, r := range in.Accounts.IdentityRecords {
		local[r.AccountName] = true
		if r.UID == 0 {
			privileged[r.AccountName] = append(privileged[r.AccountName], "UID 0")
		}
	}

	var escalations, undecided []string
	denied, used := 0, 0

	for _, e := range in.Elevations {

		times := max(e.Count, 1)
		if e.Denied {
			denied += times
			continue
		}
		used += times

		_, toPrivileged := privileged[e.To]
		_, fromPrivileged := privileged[e.From]

		switch {
		case !toPrivileged && local[e.To]:

		case fromPrivileged:
		case !local[e.From]:
			undecided = append(undecided, fmt.Sprintf("%s %s to %s (not a local account)", e.Method, e.From, e.To))
		case sudoers.BlindSpots > 0:
			undecided = append(undecided, fmt.Sprintf("%s %s to %s (sudoers has grants to unnamed accounts)", e.Method, e.From, e.To))
		default:
			cmd := ""
			if e.Command != "" {
				cmd = " running " + e.Command
			}
			escalations = append(escalations, fmt.Sprintf("%s by %s to %s%s at %s", e.Method, e.From, e.To, cmd, e.Time.UTC().Format("2006-01-02T15:04:05Z")))
		}
	}

	if len(escalations) > 0 {
		sort.Strings(escalations)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.privilege_escalations_by_unprivileged_ac", "a", escalations))
	}

	if len(undecided) > 0 {
		sort.Strings(undecided)
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.a", "a", undecided))
	}

	if used == 0 && denied == 0 && !in.Log.Reaches {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.elevations_cannot_be_seen_a", "a", in.Log.Detail))
	}

	if used == 0 && denied == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.no_sudo_or_su_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_elevations_by_privileged_accounts_or_t", "a", used, "b", denied))
}

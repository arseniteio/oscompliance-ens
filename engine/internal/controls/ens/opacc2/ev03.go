package opacc2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV03Input is what EV-03 (denied accesses and privilege escalations) needs.
type EV03Input struct {
	Accounts Accounts
	Sudoers  Sudoers
	// Elevations of the window: sudo runs and refusals, and su sessions.
	Elevations []source.Elevation
	Log        passes.AuthLog

	// Groups is P-12 (optional for this evidence).
	Groups []string
}

// JudgeEV03 judges EV-03 as described in catalog/docs/contracts/op.acc.2.md,
// from Wazuh's own sudo and su alerts:
//
//  1. Identity, group or sudoers facts unusable: NOT_EVALUABLE,
//     COLLECTION: who is privileged cannot be told.
//  2. Privileged: UID 0 accounts, members of a P-12 group and accounts with
//     a sudo grant. A sudo run or a su session that makes a non-privileged
//     account a privileged one: NON_COMPLIANT, an escalation the policy does
//     not grant. To a non-privileged account it is lateral, and fine.
//  3. An elevation by an account that is not local, or with sudoers blind
//     spots, cannot be decided: NOT_EVALUABLE, COLLECTION.
//  4. Nothing seen while the authentication log is not known to reach
//     Wazuh: NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT; refusals are
//     the control working and only reported.
func JudgeEV03(in EV03Input) verdict.Judgement {

	// 1. Who is privileged.
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
	case sudoers.Status == "unreadable":
		return passes.NotEvaluable(verdict.CauseCollection, "sudoers unreadable")
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.NotEvaluable(verdict.CauseCollection, fmt.Sprintf("sudoers read incomplete: %d of %d sudo_grant received", len(in.Sudoers.Grants), sudoers.RecordsEmitted))
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

	// 2. The elevations.
	var escalations, undecided []string
	denied, used := 0, 0

	for _, e := range in.Elevations {

		if e.Denied {
			denied++
			continue
		}
		used++

		_, toPrivileged := privileged[e.To]
		_, fromPrivileged := privileged[e.From]

		switch {
		case !toPrivileged && local[e.To]:
			// Lateral: becoming an ordinary account.
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "privilege escalations by unprivileged accounts: " + strings.Join(escalations, "; ")}
	}

	// 3. What could not be decided.
	if len(undecided) > 0 {
		sort.Strings(undecided)
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(undecided, "; "))
	}

	// 4. Silence.
	if used == 0 && denied == 0 && !in.Log.Reaches {
		return passes.NotEvaluable(verdict.CauseCollection, "elevations cannot be seen: "+in.Log.Detail)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d elevations by privileged accounts or to ordinary ones, %d refused", used, denied)}
}

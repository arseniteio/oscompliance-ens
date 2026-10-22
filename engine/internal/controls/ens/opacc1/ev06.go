package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// DefaultPrivilegedGroups is the product default for P-11, the same list v1
// applied. Used only when P-11 is not set, and the reason says so.
var DefaultPrivilegedGroups = []string{"sudo", "wheel", "admin"}

// EV06Input is what the engine knows about one agent when judging EV-06.
type EV06Input struct {
	// Groups is the newest group_snapshot in the window; nil when none.
	Groups *fact.GroupSnapshot
	// GroupRecords are the group_record facts of Groups.RunID.
	GroupRecords []fact.GroupRecord

	// Accounts are every account name of the newest complete EV-02 pass,
	// used to find "<name><suffix>" admin accounts. AccountsProblem says
	// why they are not available; "" when they are.
	Accounts        []string
	AccountsProblem string

	// Privileged is P-11. PrivilegedDefault: P-11 was not set and
	// DefaultPrivilegedGroups is used.
	Privileged        []string
	PrivilegedDefault bool

	// ConfigProblem says why P-11 or P-12 is set but unusable, naming the
	// parameter; "" when both can be used.
	ConfigProblem string

	// Suffix is P-12, "" when not set: then nobody is excluded.
	Suffix string

	// AuthSeen and Logins as in LoginInput.
	AuthSeen bool
	Logins   []source.Login
}

// JudgeEV06 judges EV-06 (one identity per role) as described in
// catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. P-11 or P-12 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Group inventory missing, unread or incomplete: NOT_EVALUABLE, COLLECTION
//     (EVIDENCE when a read snapshot has no counter).
//  3. Account list unavailable: NOT_EVALUABLE, COLLECTION.
//  4. A member of a privileged group without a separate admin identity, or a
//     login by such a member: NON_COMPLIANT.
//  5. No finding but the authentication log does not reach Wazuh:
//     NOT_EVALUABLE, COLLECTION (usage could not be checked).
//  6. Otherwise COMPLIANT.
func JudgeEV06(in EV06Input) verdict.Judgement {

	// 1. Without knowing what privilege is there is nothing to judge.
	if in.ConfigProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	// 2. The group inventory must be complete, as the account inventory.
	groups := in.Groups

	if groups == nil {
		return notEvaluable(verdict.CauseCollection, "no group_snapshot in the window")
	}

	if groups.GroupStatus != fact.SourceRead {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("%s %s: %s", groups.GroupPath, groups.GroupStatus, groups.GroupError))
	}

	if groups.RecordsEmitted == nil {
		return notEvaluable(verdict.CauseEvidence, "read group_snapshot without records_emitted")
	}

	if len(in.GroupRecords) < *groups.RecordsEmitted {
		return notEvaluable(verdict.CauseCollection,
			fmt.Sprintf("pass %s incomplete: %d of %d group_record received", groups.RunID, len(in.GroupRecords), *groups.RecordsEmitted))
	}

	// 3. "Has a separate admin identity" needs the full account list.
	if in.AccountsProblem != "" {
		return notEvaluable(verdict.CauseCollection, "account list for admin identities: "+in.AccountsProblem)
	}

	privileged := privilegedMembers(in)

	// 4a. Structural: the role has no identity of its own.
	exists := map[string]bool{}

	for _, name := range in.Accounts {
		exists[name] = true
	}

	var structural []string

	for _, name := range sortedKeys(privileged) {
		if in.Suffix != "" && exists[name+in.Suffix] {
			continue
		}
		structural = append(structural, fmt.Sprintf("%s (%s)", name, strings.Join(privileged[name], ", ")))
	}

	// 4b. Usage: a privileged member logged in with that same identity.
	usage := map[string]int{}

	for _, login := range in.Logins {
		if _, ok := privileged[login.Account]; ok {
			usage[login.Account]++
		}
	}

	var findings []string

	if len(structural) > 0 {
		findings = append(findings, "no separate admin identity: "+strings.Join(structural, "; "))
	}

	if len(usage) > 0 {
		findings = append(findings, "privileged identity used to log in: "+countList(usage))
	}

	if len(findings) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(findings, ". ")}
	}

	// 5. A measured finding stands on its own; "nothing found" needs the
	// authentication log too.
	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, "no authentication events from this agent in the lookback: privileged logins cannot be checked")
	}

	// 6. Every privileged member has a separate admin identity.
	reason := fmt.Sprintf("%d members of privileged groups (%s), none without a separate admin identity",
		len(privileged), strings.Join(in.Privileged, ", "))

	if in.PrivilegedDefault {
		reason += "; P-11 not set, product default used"
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

// privilegedMembers maps each member of a privileged group to its privileged
// groups. Members already named as admin accounts (ending in the suffix, and
// longer than it, as v1) are left out: they are the separate identity.
func privilegedMembers(in EV06Input) map[string][]string {

	isPrivileged := map[string]bool{}

	for _, name := range in.Privileged {
		isPrivileged[name] = true
	}

	members := map[string][]string{}

	for _, group := range in.GroupRecords {

		if !isPrivileged[group.GroupName] {
			continue
		}

		for _, member := range group.Members {

			if in.Suffix != "" && len(member) > len(in.Suffix) && strings.HasSuffix(member, in.Suffix) {
				continue
			}

			members[member] = append(members[member], group.GroupName)
		}
	}

	return members
}

func sortedKeys(m map[string][]string) []string {

	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

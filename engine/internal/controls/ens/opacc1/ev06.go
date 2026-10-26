package opacc1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

var DefaultPrivilegedGroups = []string{"sudo", "wheel", "admin"}

type EV06Input struct {
	Groups *fact.GroupSnapshot

	GroupRecords []fact.GroupRecord

	Accounts        []string
	AccountsProblem string

	Privileged        []string
	PrivilegedDefault bool

	ConfigProblem string

	Suffix string

	AuthSeen bool
	Logins   []source.Login
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if in.ConfigProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

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

	if in.AccountsProblem != "" {
		return notEvaluable(verdict.CauseCollection, "account list for admin identities: "+in.AccountsProblem)
	}

	privileged := privilegedMembers(in)

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

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, "no authentication events from this agent in the lookback: privileged logins cannot be checked")
	}

	reason := fmt.Sprintf("%d members of privileged groups (%s), none without a separate admin identity",
		len(privileged), strings.Join(in.Privileged, ", "))

	if in.PrivilegedDefault {
		reason += "; P-11 not set, product default used"
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

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

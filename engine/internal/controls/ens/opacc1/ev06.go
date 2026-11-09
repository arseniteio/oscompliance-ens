package opacc1

import (
	"slices"
	"sort"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var DefaultPrivilegedGroups = []string{"sudo", "wheel", "admin"}

type EV06Input struct {
	Groups *fact.GroupSnapshot

	GroupRecords []fact.GroupRecord

	Accounts        []string
	AccountsProblem catalog.Message

	Privileged        []string
	PrivilegedDefault bool

	ConfigProblem catalog.Message

	AdminAffixes []AdminAffix

	AuthSeen bool
	Logins   []source.Login
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if gap, found := passes.GroupGap(in.Groups, in.GroupRecords); found {
		return gap
	}

	if !in.AccountsProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.AccountsProblem)
	}

	privileged := privilegedMembers(in)

	exists := map[string]bool{}

	for _, name := range in.Accounts {
		exists[name] = true
	}

	var structural []catalog.Message

	for _, name := range sortedKeys(privileged) {
		if hasAdminIdentity(name, exists, in.AdminAffixes) {
			continue
		}
		structural = append(structural, catalog.Says("opacc1.member_of", "account", name, "groups", privileged[name]))
	}

	usage := map[string]int{}

	for _, login := range in.Logins {
		if _, ok := privileged[login.Account]; ok {
			usage[login.Account]++
		}
	}

	var findings []catalog.Message

	if len(structural) > 0 {
		findings = append(findings, catalog.Says("opacc1.ev06.no_admin_identity", "accounts", structural))
	}

	if len(usage) > 0 {
		findings = append(findings, catalog.Says("opacc1.ev06.privileged_login", "accounts", countList(usage)))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
	}

	if !in.AuthSeen {
		return notEvaluable(verdict.CauseCollection, catalog.Says("opacc1.ev06.no_auth_events"))
	}

	code := "opacc1.ev06.separated"
	if in.PrivilegedDefault {
		code = "opacc1.ev06.separated_default"
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says(code, "members", len(privileged), "groups", in.Privileged))
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

			if isAdminAccount(member, in.AdminAffixes) {
				continue
			}

			members[member] = append(members[member], group.GroupName)
		}
	}

	return members
}

func hasAdminIdentity(person string, exists map[string]bool, affixes []AdminAffix) bool {
	return slices.ContainsFunc(affixes, func(a AdminAffix) bool { return exists[a.accountFor(person)] })
}

func isAdminAccount(account string, affixes []AdminAffix) bool {
	return slices.ContainsFunc(affixes, func(a AdminAffix) bool { return a.marks(account) })
}

func sortedKeys(m map[string][]string) []string {

	var keys []string

	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}

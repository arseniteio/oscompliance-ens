package opacc4

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Row struct {
	Role, Resource string
	Access         []string
}

func ParseMatrix(rows []string) []Row {

	var out []Row
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		row := Row{Role: strings.TrimSpace(c[0]), Resource: strings.TrimSpace(c[1])}
		for _, a := range splitAccess(c[2]) {
			row.Access = append(row.Access, a)
		}
		if row.Role != "" {
			out = append(out, row)
		}
	}
	return out
}

func splitAccess(s string) []string {

	var out []string
	depth, start := 0, 0

	flush := func(end int) {
		if part := strings.Join(strings.Fields(s[start:end]), " "); part != "" {
			out = append(out, part)
		}
	}

	for i, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')' && depth > 0:
			depth--
		case r == ',' && depth == 0:
			flush(i)
			start = i + 1
		}
	}
	flush(len(s))

	return out
}

func Roles(rows []Row) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Role] = true
	}
	return out
}

func subject(g fact.SudoGrant) string {
	switch g.SubjectKind {
	case "group":
		return "%" + g.Subject
	case "uid":
		return "#" + g.Subject
	case "gid":
		return "%#" + g.Subject
	}
	return g.Subject
}

type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

func (s Sudoers) gap() (verdict.Judgement, bool) {
	switch {
	case s.Snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.no_sudoers_snapshot_in_the_window")), true
	case s.Snapshot.Status == fact.SourceUnreadable:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.sudoers_unreadable")), true
	case len(s.Grants) < s.Snapshot.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.sudoers_read_incomplete_a_of_b_sudo_gran", "a", len(s.Grants), "b", s.Snapshot.RecordsEmitted)), true
	}
	return verdict.Judgement{}, false
}

func (s Sudoers) blindSpots() (verdict.Judgement, bool) {
	if s.Snapshot == nil || s.Snapshot.BlindSpots == 0 {
		return verdict.Judgement{}, false
	}
	return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.sudoers_has_a_grants_to_unnamed_subjects", "a", s.Snapshot.BlindSpots, "b", strings.Join(s.Snapshot.BlindSpotReasons, "; "))), true
}

func JudgeEV02(sudoers Sudoers, rows []Row, problem string) verdict.Judgement {

	if gap, found := sudoers.gap(); found {
		return gap
	}
	if problem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc4.p_01_a", "a", problem))
	}
	if sudoers.Snapshot.Status == fact.SourceAbsent {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.sudo_is_not_installed_no_privilege_is_gr"))
	}

	byKey := map[string]Row{}
	for _, r := range rows {
		byKey[r.Role+"\x00"+r.Resource] = r
	}

	var unauthorised, gaps []string
	checked := 0

	for _, g := range sudoers.Grants {

		who := subject(g)
		row, ok := byKey[who+"\x00sudo"]

		switch {
		case !ok:
			unauthorised = append(unauthorised, fmt.Sprintf("%s %s (%s:%d): no P-01 row for %s | sudo", who, g.Spec, g.File, g.Line, who))
			continue
		case len(row.Access) == 0:
			gaps = append(gaps, who+" | sudo has no access declared")
			continue
		}

		checked++
		for _, part := range splitAccess(g.Spec) {
			if !contains(row.Access, part) {
				unauthorised = append(unauthorised, fmt.Sprintf("%s %s (%s:%d): %q not among %s", who, g.Spec, g.File, g.Line, part, strings.Join(row.Access, ", ")))
				break
			}
		}
	}

	if len(unauthorised) > 0 {
		sort.Strings(unauthorised)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.privileges_beyond_p_01_a", "a", unauthorised))
	}
	if len(gaps) > 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc4.p_01_a", "a", gaps))
	}
	if gap, blind := sudoers.blindSpots(); blind {
		return gap
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.a_sudo_grants_all_as_p_01_authorises", "a", checked))
}

type Accounts struct {
	Identity        *fact.IdentitySnapshot
	IdentityRecords []fact.IdentityRecord
	Groups          *fact.GroupSnapshot
	GroupRecords    []fact.GroupRecord
}

func (a Accounts) members(group string) []string {

	gid, found := -1, false
	var out []string

	for _, g := range a.GroupRecords {
		if g.GroupName == group {
			gid, found = g.GID, true
			out = append(out, g.Members...)
			break
		}
	}
	if !found {
		return nil
	}

	for _, r := range a.IdentityRecords {
		if r.GID == gid && !contains(out, r.AccountName) {
			out = append(out, r.AccountName)
		}
	}

	return out
}

func (a Accounts) groupsOf(account string) []string {

	var primary = -1
	for _, r := range a.IdentityRecords {
		if r.AccountName == account {
			primary = r.GID
			break
		}
	}

	var out []string
	for _, g := range a.GroupRecords {
		if g.GID == primary || contains(g.Members, account) {
			out = append(out, g.GroupName)
		}
	}
	return out
}

func (a Accounts) gap() (verdict.Judgement, bool) {
	if gap, found := passes.IdentityGap(a.Identity, a.IdentityRecords); found {
		return gap, true
	}
	return passes.GroupGap(a.Groups, a.GroupRecords)
}

func JudgeEV03(accounts Accounts, groups []string, rows []Row, problem string) verdict.Judgement {

	if gap, found := accounts.gap(); found {
		return gap
	}
	if problem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc4.a", "a", problem))
	}

	roles := Roles(rows)
	var undeclared []string
	members := 0

	for _, g := range groups {
		for _, m := range accounts.members(g) {
			members++
			if !roles[m] {
				undeclared = append(undeclared, m+" in "+g)
			}
		}
	}

	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.members_of_privileged_groups_that_are_no", "a", undeclared))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.a_memberships_of_b_all_p_01_roles", "a", members, "b", strings.Join(groups, ", ")))
}

var runasOrTag = regexp.MustCompile(`\([^)]*\)|\b[A-Z_]+:`)

func unrestricted(spec string) bool {

	_, rhs, ok := strings.Cut(spec, "=")
	if !ok {
		return false
	}

	for _, part := range splitAccess(runasOrTag.ReplaceAllString(rhs, " ")) {
		if strings.TrimSpace(part) == "ALL" {
			return true
		}
	}
	return false
}

type EV08Input struct {
	Sudoers  Sudoers
	Accounts Accounts

	UIDMin  int
	Rows    []Row
	Problem string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if gap, found := in.Sudoers.gap(); found {
		return gap
	}
	if gap, found := in.Accounts.gap(); found {
		return gap
	}
	if in.Problem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc4.p_01_a", "a", in.Problem))
	}

	roles := Roles(in.Rows)
	var excessive, declared []string

	add := func(who, why string) {
		item := who + " (" + why + ")"
		if roles[who] {
			declared = append(declared, item)
		} else {
			excessive = append(excessive, item)
		}
	}

	for _, g := range in.Sudoers.Grants {
		if unrestricted(g.Spec) {
			add(subject(g), "sudo "+g.Spec)
		}
	}

	for _, r := range in.Accounts.IdentityRecords {
		if r.UID != 0 && r.UID < in.UIDMin && loginShell(r.Shell) {
			add(r.AccountName, "system account, uid "+strconv.Itoa(r.UID)+", shell "+r.Shell)
		}
	}

	if len(excessive) > 0 {
		sort.Strings(excessive)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.privileges_above_the_minimum_not_authori", "a", excessive))
	}

	if gap, blind := in.Sudoers.blindSpots(); blind {
		return gap
	}

	if len(declared) > 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.broad_privileges_all_p_01_roles_a", "a", declared))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.no_unrestricted_sudo_grant_and_no_system"))
}

func loginShell(shell string) bool {
	for _, s := range []string{"/nologin", "/false", "/sync", "/shutdown", "/halt"} {
		if strings.HasSuffix(shell, s) {
			return false
		}
	}
	return shell != ""
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

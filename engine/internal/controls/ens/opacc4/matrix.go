package opacc4

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Row is one P-01 row: a role (a sudoers subject or an account), a
// resource and the accesses it may have.
type Row struct {
	Role, Resource string
	Access         []string
}

// ParseMatrix reads P-01, "rol | recurso | acceso,acceso".
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

// splitAccess splits an access list on commas outside parentheses, blanks
// squeezed: "ALL=(root) /usr/bin/a, /usr/bin/b" is two parts, and the same
// text in P-01 gives the same two parts (v1 compared the whole grant with
// each comma-split option, so a grant with a comma never matched).
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

// Roles is the rol column of P-01.
func Roles(rows []Row) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Role] = true
	}
	return out
}

// subject writes a sudoers subject as P-01 names it.
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

// Sudoers is one sudoers read of an agent.
type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

func (s Sudoers) gap() (verdict.Judgement, bool) {
	switch {
	case s.Snapshot == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no sudoers_snapshot in the window"), true
	case s.Snapshot.Status == fact.SourceUnreadable:
		return passes.NotEvaluable(verdict.CauseCollection, "sudoers unreadable"), true
	case len(s.Grants) < s.Snapshot.RecordsEmitted:
		return passes.NotEvaluable(verdict.CauseCollection, fmt.Sprintf("sudoers read incomplete: %d of %d sudo_grant received", len(s.Grants), s.Snapshot.RecordsEmitted)), true
	}
	return verdict.Judgement{}, false
}

// JudgeEV02 judges EV-02 (effective privileges against the matrix) as
// described in catalog/docs/contracts/op.acc.4.md:
//
//  1. Sudoers unusable: NOT_EVALUABLE, COLLECTION. P-01 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. Each sudo grant is looked up as (subject, sudo) in P-01: %group,
//     #uid and %#gid as sudoers writes them. Every part of what it grants
//     must be among the row's accesses. A grant without a row is a
//     privilege nobody authorised: NON_COMPLIANT (v1 left it
//     NOT_EVALUABLE). A row without accesses: NOT_EVALUABLE, CONFIGURATION.
//  3. Otherwise COMPLIANT; no sudo on the machine grants nothing.
func JudgeEV02(sudoers Sudoers, rows []Row, problem string) verdict.Judgement {

	if gap, found := sudoers.gap(); found {
		return gap
	}
	if problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-01: "+problem)
	}
	if sudoers.Snapshot.Status == fact.SourceAbsent {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "sudo is not installed: no privilege is granted through it"}
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "privileges beyond P-01: " + strings.Join(unauthorised, "; ")}
	}
	if len(gaps) > 0 {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-01: "+strings.Join(gaps, "; "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d sudo grants, all as P-01 authorises", checked)}
}

// Accounts is the identity and group passes of an agent.
type Accounts struct {
	Identity        *fact.IdentitySnapshot
	IdentityRecords []fact.IdentityRecord
	Groups          *fact.GroupSnapshot
	GroupRecords    []fact.GroupRecord
}

// members lists the accounts of a group, primary group included.
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

// groupsOf lists the groups of an account, primary included.
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

// JudgeEV03 judges EV-03 (members of privileged groups): every member of a
// P-06 group, primary group included, must be a role of P-01.
func JudgeEV03(accounts Accounts, groups []string, rows []Row, problem string) verdict.Judgement {

	if gap, found := accounts.gap(); found {
		return gap
	}
	if problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, problem)
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "members of privileged groups that are not a P-01 role: " + strings.Join(undeclared, ", ")}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d memberships of %s, all P-01 roles", members, strings.Join(groups, ", "))}
}

var runasOrTag = regexp.MustCompile(`\([^)]*\)|\b[A-Z_]+:`)

// unrestricted: what a grant allows includes every command (ALL).
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

// EV08Input is what EV-08 (privileges above the minimum) needs.
type EV08Input struct {
	Sudoers  Sudoers
	Accounts Accounts
	// UIDMin is login.defs UID_MIN, 1000 when not declared.
	UIDMin  int
	Rows    []Row
	Problem string
}

// JudgeEV08 judges EV-08: findings are sudo grants of every command and
// system accounts (UID below UID_MIN, not root) with a login shell. A
// finding whose subject is not a P-01 role: NON_COMPLIANT. None: COMPLIANT
// (v1 required at least one finding, so a hardened machine never passed).
func JudgeEV08(in EV08Input) verdict.Judgement {

	if gap, found := in.Sudoers.gap(); found {
		return gap
	}
	if gap, found := in.Accounts.gap(); found {
		return gap
	}
	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-01: "+in.Problem)
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "privileges above the minimum not authorised in P-01: " + strings.Join(excessive, "; ")}
	}

	if len(declared) > 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "broad privileges, all P-01 roles: " + strings.Join(declared, "; ")}
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: "no unrestricted sudo grant and no system account with a login shell"}
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

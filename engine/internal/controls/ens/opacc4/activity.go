package opacc4

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// AuditChain says why audited silence on the machine proves nothing, ""
// when it does: auditd runs, the needed rules are loaded and Wazuh reads
// the audit log.
func AuditChain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, perm bool, paths []string) string {

	switch {
	case w == nil:
		return "no audit_watch_snapshot in the window"
	case w.Auditd != fact.AuditdRunning:
		return strings.TrimSpace("auditd " + w.Auditd + " " + w.Error)
	case perm && w.PermRules == 0:
		return "the permission change rules are not loaded"
	}

	for _, p := range paths {
		watched := false
		for _, l := range w.Loaded {
			if under(p, l) {
				watched = true
			}
		}
		if !watched {
			return p + " is not watched by auditd"
		}
	}

	if c == nil || c.Status != fact.SourceRead {
		return "the Wazuh agent configuration is unknown"
	}
	for _, l := range c.Localfiles {
		if l.Format == "audit" {
			return ""
		}
	}
	return "Wazuh does not read the audit log (no localfile with log_format audit)"
}

// person names the account behind an audited access.
func person(a source.AuditAccess, accounts Accounts) string {

	for _, id := range []string{a.AUID, a.UID} {
		if id == "" || id == "unset" || id == "-1" || id == "4294967295" {
			continue
		}
		n, err := strconv.Atoi(id)
		if err != nil {
			return id
		}
		for _, r := range accounts.IdentityRecords {
			if r.UID == n {
				return r.AccountName
			}
		}
	}
	return ""
}

// JudgeEV04 judges EV-04 (rights changed by someone not competent): every
// change of mode, owner or attributes made by a person, and every write to
// the account and sudo files (key oscompliance_perm), must be by an account
// of P-02. Silence needs the audit chain with the permission rules.
func JudgeEV04(accesses []source.AuditAccess, accounts Accounts, competent []string, problem, chain string) verdict.Judgement {

	if problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-02: "+problem)
	}

	allowed := map[string]bool{}
	for _, c := range competent {
		allowed[c] = true
	}

	var others, unnamed []string
	changes := 0

	for _, a := range accesses {

		if a.Key != "oscompliance_perm" || a.Success != "yes" {
			continue
		}
		changes++

		who := person(a, accounts)
		switch {
		case who == "":
			unnamed = append(unnamed, a.Path)
		case !allowed[who]:
			others = append(others, fmt.Sprintf("%s changed %s", who, a.Path))
		}
	}

	if len(others) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "rights changed by accounts not in P-02: " + strings.Join(dedupe(others), "; ")}
	}
	if len(unnamed) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "rights changed by accounts that cannot be named: "+strings.Join(dedupe(unnamed), "; "))
	}
	if chain != "" {
		return passes.NotEvaluable(verdict.CauseCollection, chain)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d rights changes, all by accounts of P-02", changes)}
}

// ReviewParam is the register of access rights reviews, "fecha | alcance
// | responsable". The plugin does not offer it yet; v1 read a file on every
// machine.
const ReviewParam = "P-08"

// JudgeEV05 judges EV-05 (periodic review): the newest review date of the
// register, not in the future, must be within P-03 days. A future date is
// left out instead of hiding the real ones (v1 kept only the newest line).
func JudgeEV05(rows []string, rowsProblem string, maxDays int, daysProblem string, now time.Time) verdict.Judgement {

	if daysProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-03: "+daysProblem)
	}
	if rowsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, ReviewParam+" (register of access rights reviews): "+rowsProblem)
	}

	var newest time.Time
	var who string
	var bad []string

	for _, r := range rows {
		c := strings.Split(r, "|")
		date := strings.TrimSpace(c[0])
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, date); err != nil {
				bad = append(bad, date)
				continue
			}
		}
		if t.After(now) {
			bad = append(bad, date+" (in the future)")
			continue
		}
		if t.After(newest) {
			newest, who = t, strings.TrimSpace(r)
		}
	}

	if newest.IsZero() {
		if len(bad) > 0 {
			return passes.NotEvaluable(verdict.CauseEvidence, "no usable review date: "+strings.Join(bad, ", "))
		}
		return passes.NotEvaluable(verdict.CauseConfiguration, "the register has no review")
	}

	age := int(now.Sub(newest).Hours() / 24)
	if age > maxDays {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("last review %d days ago, P-03 asks every %d: %s", age, maxDays, who)}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("last review %d days ago (P-03 %d): %s", age, maxDays, who)}
}

// JudgeEV06 judges EV-06 (remote access): every remote login of the window
// must be by an account of P-05. P-05 lines are read up to the first "|",
// so an annotation does not turn an authorised account into an offender
// (v1 compared the whole line). Silence needs the auth log probe.
func JudgeEV06(logins []source.Login, authorised []string, problem string, log passes.AuthLog) verdict.Judgement {

	if problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+problem)
	}

	allowed := map[string]bool{}
	for _, a := range authorised {
		name, _, _ := strings.Cut(a, "|")
		allowed[strings.TrimSpace(name)] = true
	}

	var others []string
	remote := 0

	for _, l := range logins {
		if l.Method != source.MethodSSHD {
			continue
		}
		remote++
		if !allowed[l.Account] {
			others = append(others, fmt.Sprintf("%s from %s", l.Account, l.SourceIP))
		}
	}

	if len(others) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "remote logins by accounts not in P-05: " + strings.Join(dedupe(others), "; ")}
	}
	if remote == 0 && !log.Reaches {
		return passes.NotEvaluable(verdict.CauseCollection, "remote logins cannot be seen: "+log.Detail)
	}
	if remote == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no remote login in the window"}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d remote logins, all by accounts of P-05", remote)}
}

// Sensitive is one P-07 row: a resource and the profiles with need to know.
type Sensitive struct {
	Path     string
	Profiles map[string]bool
}

// ParseSensitive reads P-07, "recurso | perfiles".
func ParseSensitive(rows []string) []Sensitive {
	var out []Sensitive
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 2 {
			c = append(c, "")
		}
		s := Sensitive{Path: filepath.Clean(strings.TrimSpace(c[0])), Profiles: map[string]bool{}}
		for _, p := range strings.FieldsFunc(c[1], func(r rune) bool { return r == ',' || r == ' ' }) {
			s.Profiles[p] = true
		}
		out = append(out, s)
	}
	return out
}

// JudgeEV07 judges EV-07 (need to know): each audited access under a P-07
// resource (the longest that contains it: a directory covers its files,
// v1 compared the exact path) must be by an account with one of its
// profiles among its groups (primary and secondary; v1 used the primary
// group only). Silence needs auditd watching every P-07 resource.
func JudgeEV07(accesses []source.AuditAccess, accounts Accounts, resources []Sensitive, problem, chain string) verdict.Judgement {

	if problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-07: "+problem)
	}
	if gap, found := accounts.gap(); found {
		return gap
	}

	var denied, unnamed []string
	judged := 0

	for _, a := range accesses {

		if a.Success != "yes" || a.Key == "oscompliance_perm" {
			continue
		}

		best := -1
		for i, r := range resources {
			if under(a.Path, r.Path) && (best < 0 || len(r.Path) > len(resources[best].Path)) {
				best = i
			}
		}
		if best < 0 {
			continue
		}

		who := person(a, accounts)
		if who == "" {
			unnamed = append(unnamed, a.Path)
			continue
		}

		judged++
		ok := false
		for _, g := range accounts.groupsOf(who) {
			if resources[best].Profiles[g] {
				ok = true
			}
		}
		if !ok {
			denied = append(denied, fmt.Sprintf("%s on %s (groups %s)", who, a.Path, strings.Join(accounts.groupsOf(who), ",")))
		}
	}

	if len(denied) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "accesses without need to know: " + strings.Join(dedupe(denied), "; ")}
	}
	if len(unnamed) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "accesses by accounts that cannot be named: "+strings.Join(dedupe(unnamed), "; "))
	}
	if chain != "" {
		return passes.NotEvaluable(verdict.CauseCollection, chain)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d accesses to need-to-know resources, all by their profiles", judged)}
}

func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

func dedupe(list []string) []string {
	seen := map[string]int{}
	var out []string
	for _, x := range list {
		if seen[x] == 0 {
			out = append(out, x)
		}
		seen[x]++
	}
	sort.Strings(out)
	for i, x := range out {
		if n := seen[x]; n > 1 {
			out[i] = fmt.Sprintf("%s (%d times)", x, n)
		}
	}
	return out
}

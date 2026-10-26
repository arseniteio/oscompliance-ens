package opacc2

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// accessKinds names each audit key as P-06 names access types.
var accessKinds = map[string]string{
	"oscompliance_read":  "lectura",
	"oscompliance_write": "escritura",
	"oscompliance_exec":  "ejecucion",
	"oscompliance_attr":  "modificacion",
}

// EV06Input is what EV-06 (access beyond the permitted type) needs.
type EV06Input struct {
	Watches  *fact.AuditWatchSnapshot
	Config   *fact.WazuhAgentConfig
	Accesses []source.AuditAccess // audited accesses of the window
	Accounts Accounts

	// Rules is P-06 ("perfil | recurso | tipos_permitidos") and Profiles
	// P-09 ("usuario | perfil | privilegios"); Problem names an unusable
	// one.
	Rules    []string
	Profiles []string
	Problem  string
}

// JudgeEV06 judges EV-06 as described in catalog/docs/contracts/op.acc.2.md:
//
//  1. P-06 or P-09 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Each successful audited access: the person (audit uid, the login
//     identity, or the uid) gives a profile through P-09, the profile and
//     the path give a P-06 row (the longest declared path that contains it)
//     and its permitted types. A type not permitted: NON_COMPLIANT. An
//     account without a profile is counted, not judged, as v1.
//  3. Accesses that cannot be judged (no person, no row for that profile
//     and path): NOT_EVALUABLE, EVIDENCE, when nothing failed.
//  4. Silence only counts when auditd runs, every P-06 path is watched and
//     Wazuh reads the audit log: otherwise NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT.
func JudgeEV06(in EV06Input) verdict.Judgement {

	// 1. Parameters.
	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.Problem)
	}

	type rule struct {
		profile, path string
		allowed       map[string]bool
	}
	var rules []rule
	var paths []string
	for _, r := range in.Rules {
		c := cellsOf(r, 3)
		allowed := map[string]bool{}
		for _, t := range strings.FieldsFunc(c[2], func(r rune) bool { return r == ',' || r == ' ' }) {
			allowed[strings.ToLower(t)] = true
		}
		rules = append(rules, rule{profile: c[0], path: c[1], allowed: allowed})
		paths = appendNew(paths, c[1])
	}

	profileOf := map[string]string{}
	for _, r := range in.Profiles {
		c := cellsOf(r, 2)
		if c[0] != "" {
			profileOf[c[0]] = c[1]
		}
	}

	byUID := map[int]string{}
	for _, r := range in.Accounts.IdentityRecords {
		if _, seen := byUID[r.UID]; !seen {
			byUID[r.UID] = r.AccountName
		}
	}

	// 2. Every access.
	var violations, blind []string
	noProfile, judged := 0, 0

	for _, a := range in.Accesses {

		if a.Success != "yes" {
			continue // a refusal is EV-03's
		}

		kind, ok := accessKinds[a.Key]
		if !ok {
			continue
		}

		who := person(a, byUID)
		if who == "" {
			blind = append(blind, a.Path+": no person behind the access")
			continue
		}

		profile, declared := profileOf[who]
		if !declared {
			noProfile++
			continue
		}

		best := -1
		for i, r := range rules {
			if r.profile == profile && under(a.Path, r.path) && (best < 0 || len(r.path) > len(rules[best].path)) {
				best = i
			}
		}
		if best < 0 {
			blind = append(blind, fmt.Sprintf("%s (%s, profile %s): no P-06 row", a.Path, who, profile))
			continue
		}

		judged++
		if !rules[best].allowed[kind] {
			violations = append(violations, fmt.Sprintf("%s by %s (profile %s) on %s", kind, who, profile, a.Path))
		}
	}

	if len(violations) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "accesses beyond the permitted type: " + strings.Join(dedupe(violations), "; ")}
	}

	// 3. Not judgeable.
	if len(blind) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(dedupe(blind), "; "))
	}

	// 4. Silence needs the whole chain.
	if gap := auditChain(in.Watches, in.Config, paths); gap != "" {
		return passes.NotEvaluable(verdict.CauseCollection, gap)
	}

	// 5. Within the permitted types.
	reason := fmt.Sprintf("%d accesses within the types P-06 permits", judged)
	if noProfile > 0 {
		reason += fmt.Sprintf("; %d by accounts without a P-09 profile, not judged", noProfile)
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

// person is the account behind an access: the login identity, else the uid.
func person(a source.AuditAccess, byUID map[int]string) string {
	for _, id := range []string{a.AUID, a.UID} {
		if id == "" || id == "unset" || id == "-1" || id == "4294967295" {
			continue
		}
		if n, err := strconv.Atoi(id); err == nil {
			if name, ok := byUID[n]; ok {
				return name
			}
			continue
		}
		return id
	}
	return ""
}

// auditChain says why audited silence proves nothing, "" when it does.
func auditChain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, paths []string) string {

	switch {
	case w == nil:
		return "no audit_watch_snapshot in the window"
	case w.Auditd != fact.AuditdRunning:
		return "auditd " + w.Auditd + " " + w.Error
	}

	// A watch on a directory covers everything under it.
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

func cellsOf(row string, n int) []string {
	cells := strings.Split(row, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	for len(cells) < n {
		cells = append(cells, "")
	}
	return cells
}

func appendNew(list []string, v string) []string {
	if contains(list, v) {
		return list
	}
	return append(list, v)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
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

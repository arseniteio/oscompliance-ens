package opacc2

import (
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var accessKinds = map[string]string{
	"oscompliance_read":  "lectura",
	"oscompliance_write": "escritura",
	"oscompliance_exec":  "ejecucion",
	"oscompliance_attr":  "modificacion",
}

type EV06Input struct {
	Watches  *fact.AuditWatchSnapshot
	Config   *fact.WazuhAgentConfig
	Accesses []source.AuditAccess
	Accounts Accounts

	Rules    []string
	Profiles []string
	Problem  catalog.Message
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
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

	var violations, blind []catalog.Message
	noProfile, judged := 0, 0

	for _, a := range in.Accesses {

		if a.Success != "yes" {
			continue
		}

		kind, ok := accessKinds[a.Key]
		if !ok {
			continue
		}

		who := person(a, byUID)
		if who == "" {
			blind = append(blind, catalog.Says("opacc2.access_no_person", "path", a.Path))
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
			blind = append(blind, catalog.Says("opacc2.access_no_rule", "path", a.Path, "account", who, "profile", profile))
			continue
		}

		judged++
		if !rules[best].allowed[kind] {
			violations = append(violations, catalog.Says("opacc2.access_violation", "kind", catalog.Says("access."+kind), "account", who, "profile", profile, "path", a.Path))
		}
	}

	if len(violations) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.accesses_beyond_the_permitted_type_a", "a", catalog.UniqueMessages(violations)))
	}

	if len(blind) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings", "list", catalog.UniqueMessages(blind)))
	}

	if gap := auditChain(in.Watches, in.Config, paths); !gap.IsZero() {
		return passes.Gap(verdict.CauseCollection, gap)
	}

	if noProfile > 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.accesses_permitted_unprofiled", "accesses", judged, "unprofiled", noProfile))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.accesses_permitted", "accesses", judged))
}

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

func auditChain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, paths []string) catalog.Message {

	switch {
	case w == nil:
		return catalog.Says("gap.no_fact", "fact", "audit_watch_snapshot")
	case w.Auditd != fact.AuditdRunning:
		return catalog.Says("chain.auditd", "state", catalog.Says("auditd."+w.Auditd), "error", w.Error)
	}

	for _, p := range paths {
		watched := false
		for _, l := range w.Loaded {
			if under(p, l) {
				watched = true
			}
		}
		if !watched {
			return catalog.Says("chain.unwatched", "path", p)
		}
	}

	if c == nil || c.Status != fact.SourceRead {
		return catalog.Says("chain.config_unknown")
	}
	for _, l := range c.Localfiles {
		if l.Format == "audit" {
			return catalog.Message{}
		}
	}
	return catalog.Says("chain.no_audit_log")
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

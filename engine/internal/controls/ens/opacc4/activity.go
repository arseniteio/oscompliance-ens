package opacc4

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func AuditChain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, perm bool, paths []string) catalog.Message {

	switch {
	case w == nil:
		return catalog.Says("gap.no_fact", "fact", "audit_watch_snapshot")
	case w.Auditd != fact.AuditdRunning:
		return catalog.Says("chain.auditd", "state", catalog.Says("auditd."+w.Auditd), "error", w.Error)
	case perm && w.PermRules == 0:
		return catalog.Says("chain.no_perm_rules")
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

func JudgeEV04(accesses []source.AuditAccess, accounts Accounts, competent []string, problem, chain catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	allowed := map[string]bool{}
	for _, c := range competent {
		allowed[c] = true
	}

	var others []catalog.Message
	var unnamed []string
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
			others = append(others, catalog.Says("opacc4.changed_by", "account", who, "path", a.Path))
		}
	}

	if len(others) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.rights_changed_by_accounts_not_in_p_02_a", "a", catalog.UniqueMessages(others)))
	}
	if len(unnamed) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc4.rights_changed_by_accounts_that_cannot_b", "a", dedupe(unnamed)))
	}
	if !chain.IsZero() {
		return passes.Gap(verdict.CauseCollection, chain)
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.a_rights_changes_all_by_accounts_of_p_02", "a", changes))
}

const ReviewParam = "P-08"

func JudgeEV05(rows []string, rowsProblem catalog.Message, maxDays int, daysProblem catalog.Message, now time.Time) verdict.Judgement {

	if !daysProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, daysProblem)
	}
	if !rowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, rowsProblem)
	}

	var newest time.Time
	var who string
	var bad []catalog.Message

	for _, r := range rows {
		c := strings.Split(r, "|")
		date := strings.TrimSpace(c[0])
		t, err := time.Parse("2006-01-02", date)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, date); err != nil {
				bad = append(bad, catalog.Raw(date))
				continue
			}
		}
		if t.After(now) {
			bad = append(bad, catalog.Says("opacc4.future_date", "date", date))
			continue
		}
		if t.After(newest) {
			newest, who = t, strings.TrimSpace(r)
		}
	}

	if newest.IsZero() {
		if len(bad) > 0 {
			return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc4.no_usable_review_date_a", "a", bad))
		}
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc4.the_register_has_no_review"))
	}

	age := int(now.Sub(newest).Hours() / 24)
	if age > maxDays {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.last_review_a_days_ago_p_03_asks_every_b", "a", age, "b", maxDays, "c", who))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.last_review_a_days_ago_p_03_b_c", "a", age, "b", maxDays, "c", who))
}

func JudgeEV06(logins []source.Login, authorised []string, problem catalog.Message, log passes.AuthLog) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	allowed := map[string]bool{}
	for _, a := range authorised {
		name, _, _ := strings.Cut(a, "|")
		allowed[strings.TrimSpace(name)] = true
	}

	var others []catalog.Message
	remote := 0

	for _, l := range logins {
		if l.Method != source.MethodSSHD {
			continue
		}
		remote++
		if !allowed[l.Account] {
			others = append(others, catalog.Says("opacc4.login_from", "account", l.Account, "ip", l.SourceIP))
		}
	}

	if len(others) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.remote_logins_by_accounts_not_in_p_05_a", "a", catalog.UniqueMessages(others)))
	}
	if remote == 0 && !log.Reaches {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.remote_logins_cannot_be_seen_a", "a", log.Detail))
	}
	if remote == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.no_remote_login_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.a_remote_logins_all_by_accounts_of_p_05", "a", remote))
}

type Sensitive struct {
	Path     string
	Profiles map[string]bool
}

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

func JudgeEV07(accesses []source.AuditAccess, accounts Accounts, resources []Sensitive, problem, chain catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if gap, found := accounts.gap(); found {
		return gap
	}

	var denied []catalog.Message
	var unnamed []string
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
			denied = append(denied, catalog.Says("opacc4.access_by_groups", "account", who, "path", a.Path, "groups", accounts.groupsOf(who)))
		}
	}

	if len(denied) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.accesses_without_need_to_know_a", "a", catalog.UniqueMessages(denied)))
	}
	if len(unnamed) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc4.accesses_by_accounts_that_cannot_be_name", "a", dedupe(unnamed)))
	}
	if !chain.IsZero() {
		return passes.Gap(verdict.CauseCollection, chain)
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.a_accesses_to_need_to_know_resources_all", "a", judged))
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

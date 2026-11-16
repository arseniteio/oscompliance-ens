package opacc3

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Input struct {
	AgentID string
	Fleet   Fleet

	Functions []Function
	Pairs     []Pair
	Tasks     []Task

	TaskProblems []catalog.Message

	Auditors []string

	Chain catalog.Message

	Problem catalog.Message
}

func JudgePair(id string, in Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
	}

	want := requirementPair[id]
	pair, ok := declared(in.Pairs, want)
	if !ok {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc3.p_02_does_not_declare_the_pair_a_b", "a", want.Left, "b", want.Right))
	}

	if offenders := offenders(in, pair); len(offenders) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc3.incompatible_functions_a", "a", offenders))
	}

	return silence(in, catalog.Says("opacc3.pair_clean", "left", pair.Left, "right", pair.Right))
}

func JudgeTasks(in Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
	}
	if len(in.TaskProblems) > 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc3.p_04_a", "a", in.TaskProblems))
	}
	if len(in.Tasks) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc3.p_04_declares_no_critical_task"))
	}

	var short, fine []catalog.Message

	for _, t := range in.Tasks {

		key := normalize(t.Name)
		if !in.Fleet.TaskAgents[key][in.AgentID] {
			continue
		}

		people := sortedNames(in.Fleet.TaskPeople[key])
		item := catalog.Says("opacc3.task_people", "task", t.Name, "count", len(people), "required", t.Required, "people", people)

		if len(people) < t.Required {
			short = append(short, item)
		} else {
			fine = append(fine, item)
		}
	}

	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc3.critical_tasks_without_enough_people_a", "a", short))
	}

	if len(fine) > 0 && in.Chain.IsZero() {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc3.critical_tasks_run_by_enough_people_a", "a", fine))
	}

	return silence(in, catalog.Says("opacc3.no_task_run"))
}

func JudgeAuditors(in Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
	}

	pair, wildcard := declared(in.Pairs, requirementPair["EV-05"])
	if !wildcard && len(in.Auditors) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc3.neither_p_02_declares_auditoria_nor_p_05"))
	}

	var found []catalog.Message
	if wildcard {
		found = offenders(in, pair)
	}

	for _, a := range in.Auditors {

		p, ok := in.Fleet.People[a]
		if !ok || !p.Agents[in.AgentID] {
			continue
		}

		var other []string
		for f := range p.Functions {
			if f != "auditoria" && f != "supervision" {
				other = append(other, f+" ("+p.Examples[f]+")")
			}
		}
		if len(other) > 0 {
			sort.Strings(other)
			found = append(found, catalog.Says("opacc3.auditor_also", "account", a, "functions", other))
		}
	}

	if len(found) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", found))
	}

	return silence(in, catalog.Says("opacc3.auditors_clean"))
}

func JudgeInventory(in Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
	}

	var accounts []string
	for _, p := range in.Fleet.People {
		if p.Agents[in.AgentID] {
			accounts = append(accounts, fmt.Sprintf("%s (%s)", p.Name, strings.Join(sortedNames(p.Functions), ", ")))
		}
	}
	sort.Strings(accounts)

	if in.Fleet.Unresolved[in.AgentID] > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc3.a_actions_of_accounts_that_could_not_be", "a", in.Fleet.Unresolved[in.AgentID]))
	}

	if len(accounts) == 0 {
		return silence(in, catalog.Says("opacc3.no_action"))
	}

	if !in.Chain.IsZero() {
		return passes.Gap(verdict.CauseCollection, in.Chain)
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc3.a_accounts_acted_b", "a", len(accounts), "b", strings.Join(accounts, "; ")))
}

func JudgeSecurity(in Input) verdict.Judgement {

	if accesses := in.Fleet.Security[in.AgentID]; len(accesses) > 0 {
		sort.Strings(accesses)
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc3.accesses_to_security_information_a", "a", accesses))
	}

	return silence(in, catalog.Says("opacc3.no_security_access"))
}

func offenders(in Input, pair Pair) []catalog.Message {

	var out []catalog.Message

	for _, p := range in.Fleet.People {
		if !p.Agents[in.AgentID] || !Violates(p.Functions, pair) {
			continue
		}
		var held []string
		for _, f := range sortedNames(p.Functions) {
			if f == pair.Left || f == pair.Right || pair.Right == "*" {
				held = append(held, fmt.Sprintf("%s (%s)", f, p.Examples[f]))
			}
		}
		out = append(out, catalog.Says("opacc3.holds", "account", p.Name, "functions", strings.Join(held, " + ")))
	}

	catalog.SortMessages(out)
	return out
}

func silence(in Input, reason catalog.Message) verdict.Judgement {
	if !in.Chain.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc3.a_but_b", "a", reason, "b", in.Chain))
	}
	return verdict.Explain(verdict.Compliant, "", reason)
}

func Chain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, functions []Function) catalog.Message {

	switch {
	case w == nil:
		return catalog.Says("gap.no_fact", "fact", "audit_watch_snapshot")
	case w.Auditd != fact.AuditdRunning:
		return catalog.Says("chain.auditd", "state", catalog.Says("auditd."+w.Auditd), "error", w.Error)
	}

	var unwatched []string
	for _, f := range functions {
		for _, i := range f.Indicators {
			if !filepath.IsAbs(i) {
				continue
			}
			if !watched(w, i) {
				unwatched = append(unwatched, i)
			}
		}
	}
	if len(unwatched) > 0 {
		sort.Strings(unwatched)
		return catalog.Says("chain.unwatched_many", "paths", unwatched)
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

func watched(w *fact.AuditWatchSnapshot, path string) bool {
	for _, l := range append(append([]string{}, w.ExecLoaded...), w.Loaded...) {
		if path == l || strings.HasPrefix(path, strings.TrimSuffix(l, "/")+"/") {
			return true
		}
	}
	return false
}

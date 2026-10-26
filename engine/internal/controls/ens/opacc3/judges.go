package opacc3

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Input struct {
	AgentID string
	Fleet   Fleet

	Functions []Function
	Pairs     []Pair
	Tasks     []Task

	TaskProblems []string

	Auditors []string

	Chain string

	Problem string
}

func JudgePair(id string, in Input) verdict.Judgement {

	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.Problem)
	}

	want := requirementPair[id]
	pair, ok := declared(in.Pairs, want)
	if !ok {
		return passes.NotEvaluable(verdict.CauseConfiguration, fmt.Sprintf("P-02 does not declare the pair %s | %s", want.Left, want.Right))
	}

	if offenders := offenders(in, pair); len(offenders) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "incompatible functions: " + strings.Join(offenders, "; ")}
	}

	return silence(in, fmt.Sprintf("no account holds %s and %s", pair.Left, pair.Right))
}

func JudgeTasks(in Input) verdict.Judgement {

	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.Problem)
	}
	if len(in.TaskProblems) > 0 {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-04: "+strings.Join(in.TaskProblems, "; "))
	}
	if len(in.Tasks) == 0 {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-04 declares no critical task")
	}

	var short, fine []string

	for _, t := range in.Tasks {

		key := normalize(t.Name)
		if !in.Fleet.TaskAgents[key][in.AgentID] {
			continue
		}

		people := sortedNames(in.Fleet.TaskPeople[key])
		item := fmt.Sprintf("%s (%d of %d people: %s)", t.Name, len(people), t.Required, strings.Join(people, ", "))

		if len(people) < t.Required {
			short = append(short, item)
		} else {
			fine = append(fine, item)
		}
	}

	if len(short) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "critical tasks without enough people: " + strings.Join(short, "; ")}
	}

	if len(fine) > 0 && in.Chain == "" {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "critical tasks run by enough people: " + strings.Join(fine, "; ")}
	}

	return silence(in, "no critical task run on this machine in the window")
}

func JudgeAuditors(in Input) verdict.Judgement {

	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.Problem)
	}

	pair, wildcard := declared(in.Pairs, requirementPair["EV-05"])
	if !wildcard && len(in.Auditors) == 0 {
		return passes.NotEvaluable(verdict.CauseConfiguration, "neither P-02 declares auditoria | * nor P-05 lists audit accounts")
	}

	var found []string
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
				other = append(other, fmt.Sprintf("%s (%s)", f, p.Examples[f]))
			}
		}
		if len(other) > 0 {
			sort.Strings(other)
			found = append(found, fmt.Sprintf("audit account %s also does %s", a, strings.Join(other, ", ")))
		}
	}

	if len(found) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(found, "; ")}
	}

	return silence(in, "audit accounts hold no other function")
}

func JudgeInventory(in Input) verdict.Judgement {

	if in.Problem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, in.Problem)
	}

	var accounts []string
	for _, p := range in.Fleet.People {
		if p.Agents[in.AgentID] {
			accounts = append(accounts, fmt.Sprintf("%s (%s)", p.Name, strings.Join(sortedNames(p.Functions), ", ")))
		}
	}
	sort.Strings(accounts)

	if in.Fleet.Unresolved[in.AgentID] > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, fmt.Sprintf("%d actions of accounts that could not be named", in.Fleet.Unresolved[in.AgentID]))
	}

	if len(accounts) == 0 {
		return silence(in, "no action observed in the window")
	}

	if in.Chain != "" {
		return passes.NotEvaluable(verdict.CauseCollection, in.Chain)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d accounts acted: %s", len(accounts), strings.Join(accounts, "; "))}
}

func JudgeSecurity(in Input) verdict.Judgement {

	if accesses := in.Fleet.Security[in.AgentID]; len(accesses) > 0 {
		sort.Strings(accesses)
		return verdict.Judgement{Status: verdict.Compliant, Reason: "accesses to security information: " + strings.Join(accesses, "; ")}
	}

	return silence(in, "no access to security information in the window")
}

func offenders(in Input, pair Pair) []string {

	var out []string

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
		out = append(out, p.Name+": "+strings.Join(held, " + "))
	}

	sort.Strings(out)
	return out
}

func silence(in Input, reason string) verdict.Judgement {
	if in.Chain != "" {
		return passes.NotEvaluable(verdict.CauseCollection, reason+", but "+in.Chain)
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

func Chain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, functions []Function) string {

	switch {
	case w == nil:
		return "no audit_watch_snapshot in the window"
	case w.Auditd != fact.AuditdRunning:
		return strings.TrimSpace("auditd " + w.Auditd + " " + w.Error)
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
		return "auditd does not watch " + strings.Join(unwatched, ", ")
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

func watched(w *fact.AuditWatchSnapshot, path string) bool {
	for _, l := range append(append([]string{}, w.ExecLoaded...), w.Loaded...) {
		if path == l || strings.HasPrefix(path, strings.TrimSuffix(l, "/")+"/") {
			return true
		}
	}
	return false
}

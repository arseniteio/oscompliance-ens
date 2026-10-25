package opacc3

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Input is what every op.acc.3 judge of one agent needs.
type Input struct {
	AgentID string
	Fleet   Fleet

	Functions []Function
	Pairs     []Pair
	Tasks     []Task
	// TaskProblems: P-04 rows that cannot be used.
	TaskProblems []string
	// Auditors is the account column of P-05 (ALTO).
	Auditors []string

	// Chain says why silence on this agent proves nothing, "" when it does.
	Chain string
	// Problem names an unusable P-02, P-03 or P-06.
	Problem string
}

// JudgePair judges EV-01, EV-02 and EV-04 as described in
// catalog/docs/contracts/op.acc.3.md:
//
//  1. P-02, P-03 or P-06 unusable, or the evidence's pair not in P-02:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. A person who acted on this machine and holds both functions of the
//     pair, here or on another machine: NON_COMPLIANT.
//  3. Otherwise, when this machine's audit chain is incomplete:
//     NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
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

// JudgeTasks judges EV-03 (critical tasks need several people):
//
//  1. P-04 unusable (a row without its number of people or its command):
//     NOT_EVALUABLE, CONFIGURATION.
//  2. A task run on this machine in the window by fewer different people
//     than P-04 asks: NON_COMPLIANT. As v1, people are counted over the
//     window, not per run: two people each deploying alone on different
//     days count as two.
//  3. A task not run is not a failure. Silence needs the audit chain.
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

// JudgeAuditors judges EV-05 (audit accounts hold no other function):
// offenders are people holding auditoria and anything else when P-02 has
// the "auditoria | *" pair, and P-05 accounts with any function but
// auditoria or supervision. Neither declared: NOT_EVALUABLE,
// CONFIGURATION (v1 passed it by vacuity).
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

// JudgeInventory judges EV-06 (actions per account): what each account
// did here, classified; the audit chain decides whether it can be trusted.
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

// JudgeSecurity judges EV-07 (access to security information, r3.1): who
// read or changed Wazuh's configuration and the audit trail. It is
// reported, not judged: r3.1 applies at no level.
func JudgeSecurity(in Input) verdict.Judgement {

	if accesses := in.Fleet.Security[in.AgentID]; len(accesses) > 0 {
		sort.Strings(accesses)
		return verdict.Judgement{Status: verdict.Compliant, Reason: "accesses to security information: " + strings.Join(accesses, "; ")}
	}

	return silence(in, "no access to security information in the window")
}

// offenders: people who acted on this machine and hold both sides.
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

// silence: COMPLIANT when the audit chain of the machine is complete.
func silence(in Input, reason string) verdict.Judgement {
	if in.Chain != "" {
		return passes.NotEvaluable(verdict.CauseCollection, reason+", but "+in.Chain)
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

// Chain says why actions on a machine cannot all be seen: auditd not
// running, a P-03 binary or path not watched, or Wazuh not reading the
// audit log. "" when every indicator that is a path is watched.
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

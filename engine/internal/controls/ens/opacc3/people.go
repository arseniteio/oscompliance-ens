package opacc3

import (
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
)

// Person is what one account did across the machines in the window.
type Person struct {
	Name      string
	Functions map[string]bool
	// Examples: one action per function, for the reason.
	Examples map[string]string
	Agents   map[string]bool
}

// Task is a P-04 row: a critical task, how many different people it needs,
// and the indicators of its command.
type Task struct {
	Name       string
	Required   int
	Indicators []string
}

// Fleet is every person's actions, classified.
type Fleet struct {
	People map[string]*Person
	// TaskPeople: who ran each task; TaskAgents: where it ran.
	TaskPeople map[string]map[string]bool
	TaskAgents map[string]map[string]bool
	// Security: accesses to security information, by agent.
	Security map[string][]string
	// Unresolved: actions whose account could not be named, by agent.
	Unresolved map[string]int
}

// securityPaths are the security information of op.acc.3 r3.1: Wazuh's
// configuration and the audit trail.
var securityPaths = []string{"/var/ossec/etc", "/etc/audit", "/var/log/audit"}

// Names resolves an audit uid of one agent to an account name.
type Names func(agentID, uid string) (string, bool)

// BuildFleet classifies every action with P-03 and pools them by account
// name.
func BuildFleet(actions []source.ActionCount, functions []Function, tasks []Task, names Names) Fleet {

	f := Fleet{People: map[string]*Person{}, TaskPeople: map[string]map[string]bool{}, TaskAgents: map[string]map[string]bool{},
		Security: map[string][]string{}, Unresolved: map[string]int{}}

	for _, a := range actions {

		name, ok := account(a, names)
		if !ok {
			f.Unresolved[a.AgentID] += a.Count
			continue
		}

		p, seen := f.People[name]
		if !seen {
			p = &Person{Name: name, Functions: map[string]bool{}, Examples: map[string]string{}, Agents: map[string]bool{}}
			f.People[name] = p
		}
		p.Agents[a.AgentID] = true

		what := strings.TrimSpace(a.Exe + " " + a.Path)

		for _, fn := range Classify(functions, a.Exe, a.Path) {
			p.Functions[fn] = true
			if _, ok := p.Examples[fn]; !ok {
				p.Examples[fn] = what
			}
		}

		for _, t := range tasks {
			if matches(t.Indicators, a.Exe, a.Path) {
				key := normalize(t.Name)
				if f.TaskPeople[key] == nil {
					f.TaskPeople[key], f.TaskAgents[key] = map[string]bool{}, map[string]bool{}
				}
				f.TaskPeople[key][name] = true
				f.TaskAgents[key][a.AgentID] = true
			}
		}

		for _, s := range securityPaths {
			if a.Path == s || strings.HasPrefix(a.Path, s+"/") {
				f.Security[a.AgentID] = append(f.Security[a.AgentID], name+" "+a.Path)
				break
			}
		}
	}

	return f
}

// account names the person behind an action: sudo gives the name, auditd
// the login uid (the person even after su or sudo), else the uid.
func account(a source.ActionCount, names Names) (string, bool) {

	if a.User != "" {
		return a.User, true
	}

	for _, id := range []string{a.AUID, a.UID} {
		if id == "" || id == "unset" || id == "-1" || id == "4294967295" {
			continue
		}
		if _, err := strconv.Atoi(id); err != nil {
			return id, true
		}
		if name, ok := names(a.AgentID, id); ok {
			return name, true
		}
	}

	return "", false
}

func matches(indicators []string, exe, path string) bool {
	hay := strings.ToLower(exe + " " + path)
	for _, i := range indicators {
		if strings.Contains(hay, i) {
			return true
		}
	}
	return false
}

// ParseTasks reads P-04, "tarea | personas | indicador...". The indicators
// say which command is the task (v1 kept them in a file on every machine).
func ParseTasks(rows []string) (tasks []Task, problems []string) {

	for _, r := range rows {

		c := cells(r)
		if len(c) < 2 {
			problems = append(problems, "row "+r+": want tarea | personas | indicador")
			continue
		}

		n, err := strconv.Atoi(c[1])
		if err != nil || n < 2 {
			problems = append(problems, "row "+r+": the number of people must be 2 or more")
			continue
		}

		if len(c) < 3 {
			problems = append(problems, c[0]+": no indicator says which command it is")
			continue
		}

		t := Task{Name: c[0], Required: n}
		for _, i := range c[2:] {
			t.Indicators = append(t.Indicators, strings.ToLower(i))
		}
		tasks = append(tasks, t)
	}

	return tasks, problems
}

func sortedNames(set map[string]bool) []string {
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

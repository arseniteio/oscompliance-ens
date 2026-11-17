package opacc6

import (
	"strconv"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

const (
	securityPolicy = "secedit"
	systemAccess   = "System Access"
	windowsService = "windows"
	windowsModule  = "secpol"

	// Windows complexity asks for three of the four character classes.
	windowsComplexClasses = 3
	// LockoutDuration -1 keeps the account locked until an administrator unlocks it.
	untilAdministrator = -1
)

// accountPolicy is the Windows account policy secedit exports. The judges read it in
// place of PAM when the machine is Windows, which has no PAM facts.
type accountPolicy struct {
	values map[string]string
}

func windowsPolicy(s Settings) (accountPolicy, bool) {
	for _, f := range s.Files {
		if f.Source != securityPolicy || f.Status != fact.SourceRead {
			continue
		}
		p := accountPolicy{values: map[string]string{}}
		for _, e := range f.Entries {
			if e.Section == systemAccess {
				p.values[e.Key] = e.Value
			}
		}
		return p, true
	}
	return accountPolicy{}, false
}

func (p accountPolicy) int(key string) (int, bool, catalog.Message) {
	v, ok := p.values[key]
	if !ok {
		return 0, false, catalog.Message{}
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, true, catalog.Raw(securityPolicy + " " + key + "=" + v)
	}
	return n, true, catalog.Message{}
}

func (p accountPolicy) lockout() Lockout {

	l := Lockout{Service: windowsService, Module: windowsModule}

	deny, found, problem := p.int("LockoutBadCount")
	switch {
	case !problem.IsZero():
		l.Problem = problem
		return l
	case !found || deny == 0:
		l.Module = ""
		return l
	}
	l.Deny = deny

	minutes, found, problem := p.int("LockoutDuration")
	switch {
	case !problem.IsZero():
		l.Problem = problem
	case found && minutes != untilAdministrator && minutes != 0:
		l.UnlockSecs = minutes * 60
	}
	return l
}

func (p accountPolicy) quality() (Quality, catalog.Message) {

	q := Quality{Mechanism: windowsModule, Values: map[string]int{}}

	for criterion, key := range map[string]string{CriterionLength: "MinimumPasswordLength", CriterionHistory: "PasswordHistorySize"} {
		n, _, problem := p.int(key)
		if !problem.IsZero() {
			return q, problem
		}
		q.Values[criterion] = n
	}

	complexity, _, problem := p.int("PasswordComplexity")
	if !problem.IsZero() {
		return q, problem
	}
	if complexity == 1 {
		q.Values[CriterionClasses] = windowsComplexClasses
	}
	return q, catalog.Message{}
}

func (p accountPolicy) maxAge(maxAge int) catalog.Message {
	days, found, problem := p.int("MaximumPasswordAge")
	switch {
	case !problem.IsZero():
		return problem
	case !found:
		return catalog.Message{}
	case days <= 0:
		return catalog.Says("opacc6.windows_never_expires")
	case days > maxAge:
		return catalog.Says("opacc6.windows_max_age", "days", days, "max", maxAge)
	}
	return catalog.Message{}
}

package opacc6

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Criteria of P-10.
const (
	CriterionLength    = "longitud_minima"
	CriterionClasses   = "clases_de_caracteres"
	CriterionHistory   = "historial"
	CriterionBlocklist = "lista_de_bloqueo"
)

// EV11Input is what EV-11 (password quality) needs.
type EV11Input struct {
	PAM      PAM
	Settings Settings

	// Minimums is P-10 by criterion; MinimumsProblem says why it cannot be
	// used.
	Minimums        map[string]int
	MinimumsProblem string
}

// Quality is what the password stack of passwd enforces.
type Quality struct {
	Mechanism string // the module that checks quality
	Values    map[string]int
}

// JudgeEV11 judges EV-11 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. PAM or configuration unusable: NOT_EVALUABLE, COLLECTION. P-10
//     unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. The password stack of passwd (the service every password change goes
//     through, common-password or system-auth by include) is read:
//     pam_pwquality (rule, then pwquality.conf and its drop-ins), else
//     pam_cracklib, else pam_unix; history from pam_pwhistory (rule, then
//     pwhistory.conf) or pam_unix remember.
//  3. A criterion below its P-10 minimum: NON_COMPLIANT.
//  4. No passwd stack: NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
func JudgeEV11(in EV11Input) verdict.Judgement {

	// 1. Facts and parameter.
	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.MinimumsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-10: "+in.MinimumsProblem)
	}

	// 2. What passwd enforces.
	stack := in.PAM.Stack("passwd", "password")
	if len(stack) == 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "no password stack for passwd in /etc/pam.d")
	}

	q, problem := qualityOf(stack, in.Settings)
	if problem != "" {
		return passes.NotEvaluable(verdict.CauseCollection, problem)
	}

	// 3. Every P-10 row.
	var failing, met []string

	for _, criterion := range []string{CriterionLength, CriterionClasses, CriterionHistory, CriterionBlocklist} {

		minimum, asked := in.Minimums[criterion]
		if !asked {
			continue
		}

		got := q.Values[criterion]
		item := fmt.Sprintf("%s %d (P-10 %d)", criterion, got, minimum)

		if got < minimum {
			failing = append(failing, item)
		} else {
			met = append(met, item)
		}
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: q.Mechanism + ": " + strings.Join(failing, ", ")}
	}

	// 4. Every minimum met.
	return verdict.Judgement{Status: verdict.Compliant, Reason: q.Mechanism + ": " + strings.Join(met, ", ")}
}

// qualityOf reads the four criteria from a password stack.
func qualityOf(stack []fact.PAMRule, settings Settings) (Quality, string) {

	q := Quality{Values: map[string]int{}}

	var checker, unix, history *fact.PAMRule
	for i := range stack {
		r := &stack[i]
		switch r.Module {
		case "pam_pwquality.so", "pam_cracklib.so":
			if checker == nil {
				checker = r
			}
		case "pam_unix.so":
			if unix == nil {
				unix = r
			}
		case "pam_pwhistory.so":
			if history == nil {
				history = r
			}
		}
	}

	switch {
	case checker != nil && checker.Module == "pam_pwquality.so":
		q.Mechanism = "pam_pwquality"
		get := func(name string, def int) (int, string) { return pwqualityValue(*checker, settings, name, def) }

		var p string
		if q.Values[CriterionLength], p = get("minlen", 8); p != "" {
			return q, p
		}
		classes, p := pwqualityClasses(get)
		if p != "" {
			return q, p
		}
		q.Values[CriterionClasses] = classes
		if q.Values[CriterionBlocklist], p = get("dictcheck", 1); p != "" {
			return q, p
		}
		if q.Values[CriterionBlocklist] > 0 {
			q.Values[CriterionBlocklist] = 1
		}

	case checker != nil:
		q.Mechanism = "pam_cracklib"
		get := func(name string, def int) (int, string) { return ruleInt(*checker, name, def) }

		var p string
		if q.Values[CriterionLength], p = get("minlen", 9); p != "" {
			return q, p
		}
		classes, p := pwqualityClasses(get)
		if p != "" {
			return q, p
		}
		q.Values[CriterionClasses] = classes
		q.Values[CriterionBlocklist] = 1 // cracklib always checks its dictionary

	case unix != nil:
		// pam_unix only refuses very short passwords, and only with obscure.
		q.Mechanism = "pam_unix"
		q.Values[CriterionLength] = 1
		if _, obscure := Arg(*unix, "obscure"); obscure {
			n, p := ruleInt(*unix, "minlen", 6)
			if p != "" {
				return q, p
			}
			q.Values[CriterionLength] = n
		}

	default:
		q.Mechanism = "no quality module"
	}

	// History: pam_pwhistory remembers 10 by default (pam_pwhistory(8)).
	switch {
	case history != nil:
		n, p := pwhistoryValue(*history, settings)
		if p != "" {
			return q, p
		}
		q.Values[CriterionHistory] = n
	case unix != nil:
		n, p := ruleInt(*unix, "remember", 0)
		if p != "" {
			return q, p
		}
		q.Values[CriterionHistory] = n
	}

	return q, ""
}

// pwqualityClasses: minclass, or the number of classes made mandatory by a
// negative credit (dcredit=-1: at least one digit), whichever is larger.
func pwqualityClasses(get func(string, int) (int, string)) (int, string) {

	classes, p := get("minclass", 0)
	if p != "" {
		return 0, p
	}

	required := 0
	for _, credit := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		n, p := get(credit, 0)
		if p != "" {
			return 0, p
		}
		if n < 0 {
			required++
		}
	}

	return min(max(classes, required), 4), ""
}

// pwqualityValue: the rule's argument, else the last value of
// pwquality.conf and its drop-ins, else the default.
func pwqualityValue(r fact.PAMRule, settings Settings, name string, def int) (int, string) {

	if v, found := Arg(r, name); found {
		return atoi(r.Module, name, v)
	}

	v, unreadable, _ := settings.Lookup("/etc/security/pwquality.conf", "", name)
	if len(unreadable) > 0 {
		return 0, "pwquality configuration unreadable: " + strings.Join(unreadable, ", ")
	}
	if v.Found {
		return atoi(v.Source, name, v.Value)
	}

	return def, ""
}

// pwhistoryValue: the rule's remember, else pwhistory.conf, else 10.
func pwhistoryValue(r fact.PAMRule, settings Settings) (int, string) {

	if v, found := Arg(r, "remember"); found {
		return atoi(r.Module, "remember", v)
	}

	v, unreadable, _ := settings.Lookup("/etc/security/pwhistory.conf", "", "remember")
	if len(unreadable) > 0 {
		return 0, "pwhistory.conf unreadable"
	}
	if v.Found {
		return atoi(v.Source, "remember", v.Value)
	}

	return 10, ""
}

func ruleInt(r fact.PAMRule, name string, def int) (int, string) {
	if v, found := Arg(r, name); found {
		return atoi(r.Module, name, v)
	}
	return def, ""
}

func atoi(where, name, v string) (int, string) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Sprintf("%s: %s=%s is not a number", where, name, v)
	}
	return n, ""
}

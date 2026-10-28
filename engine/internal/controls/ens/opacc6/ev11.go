package opacc6

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

const (
	CriterionLength    = "longitud_minima"
	CriterionClasses   = "clases_de_caracteres"
	CriterionHistory   = "historial"
	CriterionBlocklist = "lista_de_bloqueo"
)

type EV11Input struct {
	PAM      PAM
	Settings Settings

	Minimums        map[string]int
	MinimumsProblem string
}

type Quality struct {
	Mechanism string
	Values    map[string]int
}

func JudgeEV11(in EV11Input) verdict.Judgement {

	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.MinimumsProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_10_a", "a", in.MinimumsProblem))
	}

	stack := in.PAM.Stack("passwd", "password")
	if len(stack) == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.no_password_stack_for_passwd_in_etc_pam"))
	}

	q, problem := qualityOf(stack, in.Settings)
	if problem != "" {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.a", "a", problem))
	}

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
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.a_b", "a", q.Mechanism, "b", failing))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_b", "a", q.Mechanism, "b", met))
}

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
		q.Values[CriterionBlocklist] = 1

	case unix != nil:

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

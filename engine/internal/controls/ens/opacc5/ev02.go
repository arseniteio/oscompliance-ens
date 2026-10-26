package opacc5

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV02Input struct {
	Services []Service
	Policies map[string]Policy

	Events []source.ServiceEvent

	MaxAttempts        int
	MaxAttemptsProblem string
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-03: "+in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var failing, unknown, fine []string

	for _, s := range in.Services {

		p := in.Policies[s.Name]

		switch {
		case !p.Found || p.Lockout == "":
			unknown = append(unknown, s.Name+": no lockout policy in its log")
		case p.Lockout == "desactivado":
			failing = append(failing, s.Name+": lockout disabled")
		case p.MaxAttempts == 0:
			unknown = append(unknown, s.Name+": lockout without a number of attempts")
		case p.MaxAttempts > in.MaxAttempts:
			failing = append(failing, fmt.Sprintf("%s: locks after %d attempts, P-03 allows %d", s.Name, p.MaxAttempts, in.MaxAttempts))
		case p.Reactivation == "automatica":
			failing = append(failing, s.Name+": reactivates accounts automatically")
		default:
			fine = append(fine, fmt.Sprintf("%s locks after %d", s.Name, p.MaxAttempts))
		}
	}

	for _, r := range longRuns(in.Events, in.MaxAttempts) {
		failing = append(failing, r)
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}

	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: strings.Join(fine, "; ") + fmt.Sprintf("; no account failed more than %d times in a row", in.MaxAttempts)}
}

func longRuns(events []source.ServiceEvent, limit int) []string {

	type state struct {
		run, longest int
		locked       bool
	}
	accounts := map[string]*state{}

	for _, e := range events {

		key := e.Service + " " + e.Usuario
		a, ok := accounts[key]
		if !ok {
			a = &state{}
			accounts[key] = a
		}

		switch {
		case e.Tipo == "bloqueo":
			a.run, a.locked = 0, true
		case e.Tipo == "desbloqueo":
			a.run, a.locked = 0, false
		case e.Tipo == "autenticacion" && e.Resultado == "exito":
			a.run, a.locked = 0, false
		case e.Tipo == "autenticacion" && e.Resultado == "fallo" && !a.locked:
			a.run++
			a.longest = max(a.longest, a.run)
		}
	}

	var out []string
	for key, a := range accounts {
		if a.longest > limit {
			out = append(out, fmt.Sprintf("%s: %d failures in a row without a lockout", key, a.longest))
		}
	}
	sort.Strings(out)

	return out
}

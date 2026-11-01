package opacc5

import (
	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type EV02Input struct {
	Services []Service
	Policies map[string]Policy

	Events []source.ServiceEvent

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var failing, unknown, fine []catalog.Message

	for _, s := range in.Services {

		p := in.Policies[s.Name]

		switch {
		case !p.Found || p.Lockout == "":
			unknown = append(unknown, catalog.Says("opacc5.no_lockout_policy", "service", s.Name))
		case p.Lockout == "desactivado":
			failing = append(failing, catalog.Says("opacc5.lockout_disabled", "service", s.Name))
		case p.MaxAttempts == 0:
			unknown = append(unknown, catalog.Says("opacc5.lockout_no_attempts", "service", s.Name))
		case p.MaxAttempts > in.MaxAttempts:
			failing = append(failing, catalog.Says("opacc5.locks_late", "service", s.Name, "attempts", p.MaxAttempts, "max", in.MaxAttempts))
		case p.Reactivation == "automatica":
			failing = append(failing, catalog.Says("opacc5.auto_reactivation", "service", s.Name))
		default:
			fine = append(fine, catalog.Says("opacc5.locks_after", "service", s.Name, "attempts", p.MaxAttempts))
		}
	}

	failing = append(failing, longRuns(in.Events, in.MaxAttempts)...)

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.lockouts_fine", "list", fine, "max", in.MaxAttempts))
}

func longRuns(events []source.ServiceEvent, limit int) []catalog.Message {

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

	var out []catalog.Message
	for key, a := range accounts {
		if a.longest > limit {
			out = append(out, catalog.Says("opacc5.failures_in_a_row", "account", key, "count", a.longest))
		}
	}
	catalog.SortMessages(out)

	return out
}

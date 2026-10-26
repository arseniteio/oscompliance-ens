package opacc5

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// EV05Input is what EV-05 (disablement after compromise or end of
// relationship) needs.
type EV05Input struct {
	Services []Service
	// Events: notices (notificacion_compromiso, fin_relacion) and
	// disablements (inhabilitacion), as far back as the index goes, oldest
	// first.
	Events []source.ServiceEvent
	Now    time.Time

	MaxHours        int
	MaxHoursProblem string
}

// JudgeEV05 judges EV-05 as described in catalog/docs/contracts/op.acc.5.md:
//
//  1. P-06 unusable or no service: NOT_EVALUABLE, CONFIGURATION.
//  2. Each notice is closed by the first disablement of the same account of
//     the same service after it; one still open counts the hours so far.
//  3. More hours than P-06: NON_COMPLIANT.
//  4. No notice ever: NOT_EVALUABLE, EVIDENCE, as v1: a service that does
//     not log its notices would otherwise pass.
//  5. Otherwise COMPLIANT.
func JudgeEV05(in EV05Input) verdict.Judgement {

	// 1. Parameter and subject.
	if in.MaxHoursProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-06: "+in.MaxHoursProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	type notice struct {
		at     time.Time
		reason string
		ref    string
	}
	open := map[string][]notice{}
	limit := time.Duration(in.MaxHours) * time.Hour

	var late, onTime []string

	measure := func(who string, n notice, end time.Time, closed bool) {
		took := end.Sub(n.at)
		item := fmt.Sprintf("%s (%s %s): %.1f hours", who, n.reason, n.ref, took.Hours())
		if !closed {
			item += " and still enabled"
		}
		switch {
		case took > limit:
			late = append(late, item)
		case closed:
			onTime = append(onTime, item)
		}
	}

	// 2. Notices and what closes them.
	for _, e := range in.Events {

		who := e.Service + " " + e.Usuario

		switch e.Tipo {
		case "notificacion_compromiso", "fin_relacion":
			ref := e.Referencia
			if ref == "" {
				ref = "no reference"
			}
			open[who] = append(open[who], notice{at: e.Time, reason: e.Tipo, ref: ref})
		case "inhabilitacion":
			for _, n := range open[who] {
				measure(who, n, e.Time, true)
			}
			delete(open, who)
		}
	}

	pending := 0
	for who, list := range open {
		for _, n := range list {
			pending++
			measure(who, n, in.Now, false)
		}
	}

	// 3. Late.
	if len(late) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("not disabled within %d hours: %s", in.MaxHours, strings.Join(late, "; "))}
	}

	// 4. Nothing to measure.
	if len(onTime) == 0 && pending == 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "the services logged no compromise or end-of-relationship notice")
	}

	// 5. On time.
	reason := fmt.Sprintf("disabled within %d hours: %s", in.MaxHours, strings.Join(onTime, "; "))
	if pending > 0 {
		reason += fmt.Sprintf("; %d notices still within the deadline", pending)
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

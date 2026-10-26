package opacc5

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV05Input struct {
	Services []Service

	Events []source.ServiceEvent
	Now    time.Time

	MaxHours        int
	MaxHoursProblem string
}

func JudgeEV05(in EV05Input) verdict.Judgement {

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

	if len(late) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("not disabled within %d hours: %s", in.MaxHours, strings.Join(late, "; "))}
	}

	if len(onTime) == 0 && pending == 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, "the services logged no compromise or end-of-relationship notice")
	}

	reason := fmt.Sprintf("disabled within %d hours: %s", in.MaxHours, strings.Join(onTime, "; "))
	if pending > 0 {
		reason += fmt.Sprintf("; %d notices still within the deadline", pending)
	}
	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

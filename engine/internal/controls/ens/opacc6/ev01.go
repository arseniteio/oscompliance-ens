package opacc6

import (
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV01Input struct {
	Settings Settings

	Log passes.AuthLog

	Sources        []string
	SourcesProblem string
}

var quietLogLevels = map[string]bool{"QUIET": true, "FATAL": true, "ERROR": true}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if in.SourcesProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-03: "+in.SourcesProblem)
	}

	local := false
	for _, s := range in.Sources {
		if strings.EqualFold(strings.TrimSpace(s), "local") {
			local = true
		}
	}
	if !local {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "P-03 lists no local source; " + strings.Join(in.Sources, ", ") + " are measured on their own servers"}
	}

	var gaps []string

	if in.Log.Known && !in.Log.Reaches {
		gaps = append(gaps, in.Log.Detail)
	}

	if gap, found := in.Settings.Gap(); found {
		if len(gaps) > 0 {
			return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(gaps, "; ")}
		}
		return gap
	}

	sshd := in.Settings.SSHD()

	switch sshd.Status {
	case fact.SourceAbsent:
	case fact.SourceRead:
		if level := strings.ToUpper(sshd.Get("loglevel")); quietLogLevels[level] {
			gaps = append(gaps, "sshd LogLevel "+level+" drops accepted and failed logins")
		}
	default:
		if len(gaps) == 0 {
			return passes.NotEvaluable(verdict.CauseCollection, "sshd -T not read: "+sshd.Error)
		}
	}

	if len(gaps) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(gaps, "; ")}
	}

	if !in.Log.Known {
		return passes.NotEvaluable(verdict.CauseCollection, in.Log.Detail)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: "the authentication log reaches Wazuh (" + in.Log.Detail + ") and sshd logs logins"}
}

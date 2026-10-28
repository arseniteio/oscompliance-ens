package opacc6

import (
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_03_a", "a", in.SourcesProblem))
	}

	local := false
	for _, s := range in.Sources {
		if strings.EqualFold(strings.TrimSpace(s), "local") {
			local = true
		}
	}
	if !local {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.p_03_lists_no_local_source_a_are_measure", "a", in.Sources))
	}

	var gaps []string

	if in.Log.Known && !in.Log.Reaches {
		gaps = append(gaps, in.Log.Detail)
	}

	if gap, found := in.Settings.Gap(); found {
		if len(gaps) > 0 {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.a", "a", gaps))
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
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.sshd_t_not_read_a", "a", sshd.Error))
		}
	}

	if len(gaps) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.a", "a", gaps))
	}

	if !in.Log.Known {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.a", "a", in.Log.Detail))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.the_authentication_log_reaches_wazuh_a_a", "a", in.Log.Detail))
}

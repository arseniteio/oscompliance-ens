package opacc6

import (
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// EV01Input is what EV-01 (logging of successful and failed accesses) needs.
type EV01Input struct {
	Settings Settings

	// Log says whether the authentication log reaches Wazuh (the probe).
	Log passes.AuthLog

	// Sources is P-03; SourcesProblem says why it cannot be used.
	Sources        []string
	SourcesProblem string
}

// quietLogLevels silence the Accepted and Failed lines of sshd.
var quietLogLevels = map[string]bool{"QUIET": true, "FATAL": true, "ERROR": true}

// JudgeEV01 judges EV-01 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. P-03 unusable: NOT_EVALUABLE, CONFIGURATION. P-03 without "local":
//     COMPLIANT, the directory sources are measured on their own servers.
//  2. Gaps of the local source: the agent's probe line, written each pass to
//     the authpriv facility, never came back as a Wazuh alert (the log is
//     not written or not collected), or sshd logs below INFO, which drops
//     its Accepted and Failed lines.
//  3. A gap: NON_COMPLIANT. The probe or the sshd configuration not known:
//     NOT_EVALUABLE, COLLECTION. Otherwise COMPLIANT.
func JudgeEV01(in EV01Input) verdict.Judgement {

	// 1. Which sources must log.
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

	// 2. The gaps.
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

	// 3. Verdict.
	if len(gaps) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(gaps, "; ")}
	}

	if !in.Log.Known {
		return passes.NotEvaluable(verdict.CauseCollection, in.Log.Detail)
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: "the authentication log reaches Wazuh (" + in.Log.Detail + ") and sshd logs logins"}
}

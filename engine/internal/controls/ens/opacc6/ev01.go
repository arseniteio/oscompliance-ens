package opacc6

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV01Input is what EV-01 (logging of successful and failed accesses) needs.
type EV01Input struct {
	Settings Settings

	// LastAuthEvent is the newest authentication alert of the agent in the
	// lookback, zero when there is none.
	LastAuthEvent time.Time
	Lookback      time.Duration

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
//  2. Gaps of the local source: no authentication event of the machine
//     reached Wazuh in the lookback (cron alone opens a PAM session every
//     hour, so silence means the log is not collected), or sshd logs below
//     INFO, which drops its Accepted and Failed lines.
//  3. A gap: NON_COMPLIANT. sshd configuration not readable: NOT_EVALUABLE,
//     COLLECTION. Otherwise COMPLIANT.
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

	if in.LastAuthEvent.IsZero() {
		gaps = append(gaps, fmt.Sprintf("no authentication event of this machine reached Wazuh in %s", in.Lookback))
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

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: "authentication events reach Wazuh (newest " + in.LastAuthEvent.UTC().Format(time.RFC3339) + ") and sshd logs logins",
	}
}

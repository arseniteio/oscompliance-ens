package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV02Input is what EV-02 (integrity of the critical OS files) needs.
type EV02Input struct {
	// Config is what the Wazuh agent watches; nil when not reported.
	Config  *fact.WazuhAgentConfig
	Changes []source.FIMChange // FIM alerts of the window
	Window  time.Duration

	// Critical is P-02; CriticalProblem says why it cannot be used.
	Critical        []string
	CriticalProblem string
}

// JudgeEV02 judges EV-02 as described in catalog/docs/contracts/op.acc.2.md,
// from Wazuh's own file integrity monitoring:
//
//  1. P-02 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. A FIM alert of the window on a P-02 path, or under a P-02 directory:
//     NON_COMPLIANT, as v1: every change of a critical file is reported,
//     there is no list of expected changes.
//  3. A P-02 path FIM does not watch (no <directories> covers it, it is
//     ignored, FIM is off, or scans are further apart than the window and
//     not in real time): NOT_EVALUABLE, COLLECTION. The Wazuh configuration
//     not reported: the same.
//  4. Otherwise COMPLIANT.
func JudgeEV02(in EV02Input) verdict.Judgement {

	// 1. Parameter.
	if in.CriticalProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-02: "+in.CriticalProblem)
	}

	// 2. Changes on critical paths.
	var changed []string
	for _, c := range in.Changes {
		for _, p := range in.Critical {
			if under(c.Path, p) {
				what := c.Event
				if len(c.Changed) > 0 {
					what += " (" + strings.Join(c.Changed, ",") + ")"
				}
				changed = append(changed, fmt.Sprintf("%s %s at %s", c.Path, what, c.Time.UTC().Format(time.RFC3339)))
				break
			}
		}
	}

	if len(changed) > 0 {
		sort.Strings(changed)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "critical files changed: " + strings.Join(changed, "; ")}
	}

	// 3. Silence is only proof where FIM looks.
	switch {
	case in.Config == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no wazuh_agent_config in the window: what FIM watches is unknown")
	case in.Config.Status != fact.SourceRead:
		return passes.NotEvaluable(verdict.CauseCollection, "Wazuh agent configuration "+in.Config.Status+": "+in.Config.Error)
	case in.Config.SyscheckDisabled:
		return passes.NotEvaluable(verdict.CauseCollection, "Wazuh FIM is disabled on this machine")
	}

	var unwatched []string
	for _, p := range in.Critical {
		if why := notWatched(*in.Config, p, in.Window); why != "" {
			unwatched = append(unwatched, p+" ("+why+")")
		}
	}

	if len(unwatched) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, "critical paths FIM does not watch in time: "+strings.Join(unwatched, ", "))
	}

	// 4. Watched and unchanged.
	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d critical paths watched by Wazuh FIM, no change in the window", len(in.Critical))}
}

// notWatched says why FIM does not cover a path within the window, "" when
// it does.
func notWatched(c fact.WazuhAgentConfig, path string, window time.Duration) string {

	for _, i := range c.Ignored {
		if under(path, i) {
			return "ignored by " + i
		}
	}

	for _, d := range c.Directories {
		if !under(path, d.Path) {
			continue
		}
		if d.Realtime || d.Whodata {
			return ""
		}
		if c.SyscheckFrequency == 0 || time.Duration(c.SyscheckFrequency)*time.Second <= window {
			return ""
		}
		return fmt.Sprintf("scanned every %d s, longer than the window", c.SyscheckFrequency)
	}

	return "no FIM directory covers it"
}

// under: path is dir itself or inside it.
func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

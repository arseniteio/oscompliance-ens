package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV02Input struct {
	Config  *fact.WazuhAgentConfig
	Changes []source.FIMChange
	Window  time.Duration

	Critical        []string
	CriticalProblem string
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if in.CriticalProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-02: "+in.CriticalProblem)
	}

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

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d critical paths watched by Wazuh FIM, no change in the window", len(in.Critical))}
}

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

func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

package opacc2

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.p_02_a", "a", in.CriticalProblem))
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
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.critical_files_changed_a", "a", changed))
	}

	switch {
	case in.Config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_wazuh_agent_config_in_the_window_what"))
	case in.Config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.wazuh_agent_configuration_a_b", "a", in.Config.Status, "b", in.Config.Error))
	case in.Config.SyscheckDisabled:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.wazuh_fim_is_disabled_on_this_machine"))
	}

	var unwatched []string
	for _, p := range in.Critical {
		if why := notWatched(*in.Config, p, in.Window); why != "" {
			unwatched = append(unwatched, p+" ("+why+")")
		}
	}

	if len(unwatched) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.critical_paths_fim_does_not_watch_in_tim", "a", unwatched))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_critical_paths_watched_by_wazuh_fim_no", "a", len(in.Critical)))
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

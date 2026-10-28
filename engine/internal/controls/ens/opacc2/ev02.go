package opacc2

import (
	"path/filepath"
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
	CriticalProblem catalog.Message
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if !in.CriticalProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.CriticalProblem)
	}

	var changed []catalog.Message
	for _, c := range in.Changes {
		for _, p := range in.Critical {
			if under(c.Path, p) {
				event := catalog.Says("fim." + c.Event)
				if len(c.Changed) > 0 {
					event = catalog.Says("opacc2.fim_event_fields", "event", event, "fields", c.Changed)
				}
				changed = append(changed, catalog.Says("opacc2.file_changed", "path", c.Path, "event", event, "at", c.Time.UTC().Format(time.RFC3339)))
				break
			}
		}
	}

	if len(changed) > 0 {
		catalog.SortMessages(changed)
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

	var unwatched []catalog.Message
	for _, p := range in.Critical {
		if why := notWatched(*in.Config, p, in.Window); !why.IsZero() {
			unwatched = append(unwatched, catalog.Says("item.path_why", "path", p, "why", why))
		}
	}

	if len(unwatched) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.critical_paths_fim_does_not_watch_in_tim", "a", unwatched))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_critical_paths_watched_by_wazuh_fim_no", "a", len(in.Critical)))
}

func notWatched(c fact.WazuhAgentConfig, path string, window time.Duration) catalog.Message {

	for _, i := range c.Ignored {
		if under(path, i) {
			return catalog.Says("opacc2.fim_ignored", "rule", i)
		}
	}

	for _, d := range c.Directories {
		if !under(path, d.Path) {
			continue
		}
		if d.Realtime || d.Whodata {
			return catalog.Message{}
		}
		if c.SyscheckFrequency == 0 || time.Duration(c.SyscheckFrequency)*time.Second <= window {
			return catalog.Message{}
		}
		return catalog.Says("opacc2.fim_slow", "seconds", c.SyscheckFrequency)
	}

	return catalog.Says("opacc2.fim_uncovered")
}

func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

package winaudit

import (
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

const (
	DefaultSuspend = time.Hour
	MaxEvents      = 2000

	maskReadData = 0x1
)

type GuardState struct {
	Bookmark  int64                `json:"bookmark"`
	Last      time.Time            `json:"last"`
	Suspended map[string]time.Time `json:"suspended"`
}

type event struct {
	Record  int64  `json:"record"`
	Time    string `json:"time"`
	Account string `json:"account"`
	Domain  string `json:"domain"`
	Object  string `json:"object"`
	Mask    string `json:"mask"`
	Process string `json:"process"`
}

type guardOutput struct {
	Newest int64   `json:"newest"`
	Events []event `json:"events"`
}

type Suspension struct {
	Path  string
	Until time.Time
	Reads int
}

type GuardConfig struct {
	Managed string
	State   string
	Limit   int
	Suspend time.Duration
}

// Guard forwards the accesses Windows logged on the watched paths since the
// last run as file_access facts, oldest first and at most MaxEvents a run so
// the bookmark never skips one, and removes the read entry of a watch whose
// reads go over Limit per minute: event 4663 has no rate limit of its own.
func Guard(e *emit.Emitter, run winps.Runner, cfg GuardConfig, now time.Time) ([]Suspension, error) {

	var managed Managed
	if err := readJSON(cfg.Managed, &managed); err != nil {
		return nil, err
	}
	var state GuardState
	if err := readJSON(cfg.State, &state); err != nil {
		return nil, err
	}
	if state.Suspended == nil {
		state.Suspended = map[string]time.Time{}
	}
	for path, until := range state.Suspended {
		if !now.Before(until) {
			delete(state.Suspended, path)
		}
	}

	script, err := winps.WithInput(map[string]int64{"since": state.Bookmark, "max": MaxEvents}, guardScript)
	if err != nil {
		return nil, err
	}
	out, err := winps.Decode[guardOutput](run, script)
	if err != nil {
		return nil, err
	}

	bookmark := out.Newest
	if len(out.Events) == MaxEvents {
		bookmark = out.Events[len(out.Events)-1].Record
	}

	reads := map[string]int{}
	for _, ev := range out.Events {
		w, ok := watchOf(ev.Object, managed.Watches)
		if !ok {
			continue
		}
		access := fact.AccessWrite
		if parseMask(ev.Mask)&maskReadData != 0 && w.Access == fact.AccessRead {
			access = fact.AccessRead
			reads[w.Path]++
		}
		if err := e.Emit(fact.FileAccess{Envelope: e.Envelope(fact.FileAccessFact), Time: ev.Time, Watch: w.Path, Path: ev.Object, Access: access, Account: ev.Account, Domain: ev.Domain, Process: ev.Process}); err != nil {
			return nil, err
		}
	}

	minutes := now.Sub(state.Last).Minutes()
	if state.Last.IsZero() || minutes < 1 {
		minutes = 1
	}

	var suspended []Suspension
	var unset []Watch
	for _, w := range managed.Watches {
		if n := reads[w.Path]; w.Access == fact.AccessRead && float64(n) > float64(cfg.Limit)*minutes {
			until := now.Add(cfg.Suspend)
			state.Suspended[w.Path] = until
			suspended = append(suspended, Suspension{Path: w.Path, Until: until, Reads: n})
			unset = append(unset, w)
		}
	}
	if len(unset) > 0 {
		if _, err := applySACL(run, saclInput{Set: []Watch{}, Unset: unset}); err != nil {
			return suspended, fmt.Errorf("suspend: %w", err)
		}
	}

	state.Bookmark, state.Last = bookmark, now
	return suspended, writeJSON(cfg.State, state)
}

func watchOf(object string, watches []Watch) (Watch, bool) {

	var best Watch
	found := false
	for _, w := range watches {
		if under(object, w.Path) && (!found || len(w.Path) > len(best.Path)) {
			best, found = w, true
		}
	}
	return best, found
}

func under(object, dir string) bool {
	o, d := strings.ToLower(object), strings.TrimRight(strings.ToLower(dir), `\`)
	return o == d || strings.HasPrefix(o, d+`\`)
}

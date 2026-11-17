package winaudit

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

var (
	//go:embed sacl.ps1
	saclScript string
	//go:embed guard.ps1
	guardScript string
)

type Watch struct {
	Path   string `json:"path"`
	Access string `json:"access"`
}

type saclInput struct {
	Set   []Watch `json:"set"`
	Unset []Watch `json:"unset"`
}

type saclFailure struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

type saclOutput struct {
	Loaded  []string      `json:"loaded"`
	Failed  []saclFailure `json:"failed"`
	Removed []string      `json:"removed"`
}

type Config struct {
	Wazuh   wazuh.AgentConfigPaths
	Managed string
	Guard   string
}

// Managed holds the SACL entries this agent added, so a later pass removes
// exactly those and never an entry an administrator set.
type Managed struct {
	Watches []Watch `json:"watches"`
}

func Collect(e *emit.Emitter, run winps.Runner, cfg Config, now time.Time) error {

	s := fact.AuditWatchSnapshot{Envelope: e.Envelope(fact.AuditWatchSnapshotFact), Auditd: fact.AuditdRunning, Wanted: []string{}, Loaded: []string{}}

	shared, _, err := wazuh.ReadSharedPaths(cfg.Wazuh)
	if err != nil {
		s.Auditd, s.Error = fact.AuditdError, err.Error()
		return e.Emit(s)
	}

	var managed Managed
	if err := readJSON(cfg.Managed, &managed); err != nil {
		s.Auditd, s.Error = fact.AuditdError, err.Error()
		return e.Emit(s)
	}
	var guard GuardState
	if err := readJSON(cfg.Guard, &guard); err != nil {
		s.Auditd, s.Error = fact.AuditdError, err.Error()
		return e.Emit(s)
	}

	wanted := Wanted(shared)
	set, unset := Plan(wanted, managed.Watches, guard.Suspended, now)

	for _, w := range wanted {
		s.Wanted = append(s.Wanted, w.Path)
		if w.Access == fact.AccessRead {
			s.ReadWanted = append(s.ReadWanted, w.Path)
		}
	}

	out, err := winps.Decode[saclOutput](run, input(saclInput{Set: set, Unset: unset})+saclScript)
	if err != nil {
		s.Auditd, s.Error = fact.AuditdError, err.Error()
		return e.Emit(s)
	}

	s.Loaded = append(s.Loaded, out.Loaded...)
	s.Unloaded = out.Removed
	for _, f := range out.Failed {
		s.Failed = append(s.Failed, f.Path+": "+f.Error)
	}

	next := Managed{Watches: []Watch{}}
	for _, w := range set {
		if slices.Contains(out.Loaded, w.Path) {
			next.Watches = append(next.Watches, w)
		}
	}
	if err := writeJSON(cfg.Managed, next); err != nil {
		return fmt.Errorf("managed watches: %w", err)
	}

	return e.Emit(s)
}

func Wanted(p wazuh.SharedPaths) []Watch {

	var out []Watch
	add := func(paths []string, access string) {
		for _, path := range paths {
			if Absolute(path) && !slices.ContainsFunc(out, func(w Watch) bool { return strings.EqualFold(w.Path, path) }) {
				out = append(out, Watch{Path: path, Access: access})
			}
		}
	}
	add(p.ReadWatches, fact.AccessRead)
	add(p.AuditWatches, fact.AccessWrite)
	return out
}

func Plan(wanted, managed []Watch, suspended map[string]time.Time, now time.Time) (set, unset []Watch) {

	set, unset = []Watch{}, []Watch{}
	active := func(w Watch) bool {
		until, ok := suspended[w.Path]
		return !(ok && w.Access == fact.AccessRead && now.Before(until))
	}

	for _, w := range wanted {
		if active(w) {
			set = append(set, w)
		}
	}
	for _, m := range managed {
		if !slices.Contains(set, m) {
			unset = append(unset, m)
		}
	}
	return set, unset
}

func input(v any) string {
	data, _ := json.Marshal(v)
	return "$in = ConvertFrom-Json '" + strings.ReplaceAll(string(data), "'", "''") + "'\n"
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseMask(s string) uint64 {
	s = strings.TrimSpace(s)
	if hex, ok := strings.CutPrefix(strings.ToLower(s), "0x"); ok {
		n, _ := strconv.ParseUint(hex, 16, 64)
		return n
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func Absolute(path string) bool {
	if strings.HasPrefix(path, `\\`) {
		return true
	}
	return len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') &&
		(path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z')
}

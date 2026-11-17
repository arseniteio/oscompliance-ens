package winpolicy

import (
	_ "embed"
	"maps"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed policy.ps1
var script string

const (
	SecurityPolicy = "secedit"
	AuditPolicy    = "auditpol"
)

type registryKey struct {
	Path   string            `json:"path"`
	Exists bool              `json:"exists"`
	Values map[string]string `json:"values"`
}

type auditSetting struct {
	Subcategory string `json:"subcategory"`
	GUID        string `json:"guid"`
	Value       string `json:"value"`
}

type output struct {
	Secedit       []string       `json:"secedit"`
	SeceditError  string         `json:"secedit_error"`
	Auditpol      []auditSetting `json:"auditpol"`
	AuditpolError string         `json:"auditpol_error"`
	Registry      []registryKey  `json:"registry"`
}

var skippedSections = []string{"unicode", "version"}

func Collect(e *emit.Emitter, run winps.Runner) error {

	snapshot := fact.ConfigSnapshot{Envelope: e.Envelope(fact.ConfigSnapshotFact)}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		failed := source(e, SecurityPolicy)
		failed.Status, failed.Error = fact.SourceError, err.Error()
		if err := e.Emit(failed); err != nil {
			return err
		}
		snapshot.RecordsEmitted = 1
		return e.Emit(snapshot)
	}

	sources := []fact.ConfigFile{securityPolicy(e, out), auditPolicy(e, out)}
	for _, k := range out.Registry {
		sources = append(sources, registry(e, k))
	}

	for _, s := range sources {
		if err := e.Emit(s); err != nil {
			return err
		}
		snapshot.RecordsEmitted++
	}

	return e.Emit(snapshot)
}

func source(e *emit.Emitter, name string) fact.ConfigFile {
	return fact.ConfigFile{Envelope: e.Envelope(fact.ConfigFileFact), Source: name, Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}
}

func securityPolicy(e *emit.Emitter, out output) fact.ConfigFile {

	s := source(e, SecurityPolicy)
	if out.SeceditError != "" {
		s.Status, s.Error = fact.SourceError, out.SeceditError
		return s
	}
	s.Entries = ParseINI(out.Secedit)
	return s
}

func ParseINI(lines []string) []fact.ConfigEntry {

	entries := []fact.ConfigEntry{}
	section := ""
	for i, raw := range lines {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
		switch {
		case line == "" || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		case slices.Contains(skippedSections, strings.ToLower(section)):
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		entries = append(entries, fact.ConfigEntry{Key: strings.TrimSpace(key), Value: unquote(strings.TrimSpace(value)), Line: i + 1, Section: section})
	}
	return entries
}

func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

func auditPolicy(e *emit.Emitter, out output) fact.ConfigFile {

	s := source(e, AuditPolicy)
	if out.AuditpolError != "" {
		s.Status, s.Error = fact.SourceError, out.AuditpolError
		return s
	}
	for _, a := range out.Auditpol {
		s.Entries = append(s.Entries, fact.ConfigEntry{Key: strings.ToUpper(strings.Trim(a.GUID, "{}")), Value: a.Value, Section: a.Subcategory})
	}
	return s
}

func registry(e *emit.Emitter, k registryKey) fact.ConfigFile {

	s := fact.ConfigFile{Envelope: e.Envelope(fact.ConfigFileFact), Source: k.Path, Kind: fact.ConfigKindFile, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}
	if !k.Exists {
		s.Status = fact.SourceAbsent
		return s
	}
	for _, name := range slices.Sorted(maps.Keys(k.Values)) {
		s.Entries = append(s.Entries, fact.ConfigEntry{Key: name, Value: k.Values[name]})
	}
	return s
}

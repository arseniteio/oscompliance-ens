package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
)

//go:embed controls templates
var files embed.FS

type Control struct {
	Framework    string               `json:"framework"`
	Control      string               `json:"control"`
	Title        string               `json:"title"`
	Status       string               `json:"status"`
	Requirements []Requirement        `json:"requirements"`
	Evidences    []Evidence           `json:"evidences"`
	Parameters   map[string]Parameter `json:"parameters"`
}

type Requirement struct {
	ID                  string   `json:"id"`
	Title               string   `json:"title"`
	Levels              []string `json:"levels"`
	EvidenceIDs         []string `json:"evidence_ids"`
	ApplicabilityReason string   `json:"applicability_reason,omitempty"`
}

func (r Requirement) AppliesAt(level string) bool {
	return slices.Contains(r.Levels, level)
}

type Evidence struct {
	ID           string   `json:"id"`
	Levels       []string `json:"levels"`
	Requirements []string `json:"requirements"`
}

const (
	ClassOrganisation = "organisation"

	ClassSystem = "system"

	ClassPlatform = "platform"
)

type Parameter struct {
	Class string `json:"class"`
}

type Template struct {
	ID          string                       `json:"id"`
	Name        string                       `json:"name"`
	Kind        string                       `json:"kind"`
	SystemType  string                       `json:"system_type"`
	TypeDefault bool                         `json:"type_default"`
	Values      map[string]map[string]any    `json:"values"`
	MatchModes  map[string]map[string]string `json:"match_modes,omitempty"`
}

var (
	controls  = map[string]Control{}
	templates []Template
)

func init() {

	err := fs.WalkDir(files, "controls", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".json" {
			return err
		}
		var c Control
		if err := decodeStrict(p, &c); err != nil {
			return err
		}
		controls[c.Control] = c
		return nil
	})
	if err != nil {
		panic(err)
	}

	entries, err := fs.ReadDir(files, "templates")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		var t Template
		if err := decodeStrict(path.Join("templates", e.Name()), &t); err != nil {
			panic(err)
		}
		templates = append(templates, t)
	}
}

func decodeStrict(p string, v any) error {

	raw, err := files.ReadFile(p)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("catalog %s: %w", p, err)
	}

	return nil
}

func Controls() []Control {

	var out []Control

	for _, c := range controls {
		out = append(out, c)
	}

	slices.SortFunc(out, func(a, b Control) int { return strings.Compare(a.Control, b.Control) })

	return out
}

func LookupControl(id string) (Control, bool) {
	c, ok := controls[id]
	return c, ok
}

func (c Control) Evidence(id string) (Evidence, bool) {
	for _, e := range c.Evidences {
		if e.ID == id {
			return e, true
		}
	}
	return Evidence{}, false
}

func (e Evidence) AppliesAt(level string) bool {
	return slices.Contains(e.Levels, level)
}

func ParameterClass(controlID, paramID string) string {
	return controls[controlID].Parameters[paramID].Class
}

func IsAgentLevel(controlID, paramID string) bool {
	class := ParameterClass(controlID, paramID)
	return class == ClassSystem || class == ClassPlatform
}

func BuiltinTemplate(id, controlID string) (Template, bool) {
	for _, t := range templates {
		if t.ID == id && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

func TypeDefaultTemplate(controlID, systemType string) (Template, bool) {
	for _, t := range templates {
		if t.TypeDefault && t.SystemType == systemType && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

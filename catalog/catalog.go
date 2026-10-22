// Package catalog is the single source of what the engine needs to know about
// each control and is not policy: which evidences exist and at which ENS
// levels they apply, the class of each parameter, and the built-in
// templates. The data lives in JSON next to this file (controls/, templates/)
// so the plugin can read the same files.
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

// Control is one control file of controls/.
type Control struct {
	Framework  string               `json:"framework"`
	Control    string               `json:"control"`
	Title      string               `json:"title"`
	Evidences  []Evidence           `json:"evidences"`
	Parameters map[string]Parameter `json:"parameters"`
}

// Evidence is one evidence of a control.
type Evidence struct {
	ID           string   `json:"id"`
	Levels       []string `json:"levels"`
	Requirements []string `json:"requirements"`
}

// Parameter classes, as the plugin defines them.
const (
	// ClassOrganisation: one value for the whole organisation; an agent
	// value is ignored.
	ClassOrganisation = "organisation"
	// ClassSystem: per machine, set on the agent.
	ClassSystem = "system"
	// ClassPlatform: per kind of machine, usually from a template.
	ClassPlatform = "platform"
)

// Parameter is what the catalog knows about one parameter of a control.
type Parameter struct {
	Class string `json:"class"`
}

// Template is one built-in template of templates/: parameter values for a
// kind of system, by control.
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

// init loads the embedded data once. A malformed file is a build defect,
// caught by the package tests, so it panics here.
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

// LookupControl returns a control by id.
func LookupControl(id string) (Control, bool) {
	c, ok := controls[id]
	return c, ok
}

// Evidence returns one evidence of the control.
func (c Control) Evidence(id string) (Evidence, bool) {
	for _, e := range c.Evidences {
		if e.ID == id {
			return e, true
		}
	}
	return Evidence{}, false
}

// AppliesAt says whether the evidence applies at an ENS level.
func (e Evidence) AppliesAt(level string) bool {
	return slices.Contains(e.Levels, level)
}

// ParameterClass returns the class of a parameter; "" when the catalog does
// not know it, which callers treat as organisation (the plugin does too).
func ParameterClass(controlID, paramID string) string {
	return controls[controlID].Parameters[paramID].Class
}

// IsAgentLevel: the parameter can have a value per agent or from a template.
func IsAgentLevel(controlID, paramID string) bool {
	class := ParameterClass(controlID, paramID)
	return class == ClassSystem || class == ClassPlatform
}

// BuiltinTemplate returns a built-in template that has values for the control.
func BuiltinTemplate(id, controlID string) (Template, bool) {
	for _, t := range templates {
		if t.ID == id && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

// TypeDefaultTemplate returns the built-in template a system type gets for a
// control when none is assigned.
func TypeDefaultTemplate(controlID, systemType string) (Template, bool) {
	for _, t := range templates {
		if t.TypeDefault && t.SystemType == systemType && t.Values[controlID] != nil {
			return t, true
		}
	}
	return Template{}, false
}

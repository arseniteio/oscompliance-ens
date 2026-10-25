// Package params reads policy parameters from the plugin's configuration
// index, so each parameter lives in one place: the Configuration screen.
package params

import (
	"context"

	"errors"
	"fmt"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog"
	"regexp"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/indexer"
)

// ErrNotSet: the parameter is missing or empty. Judging against a default the
// auditor never set would be a lie, so callers turn this into NOT_EVALUABLE
// with cause CONFIGURATION.
var ErrNotSet = errors.New("not set")

// Config is the plugin's active configuration, reduced to what the engine reads.
type Config struct {
	Global struct {
		EnsLevel string `json:"ensLevel"`
	} `json:"global"`
	Controls []struct {
		ControlID  string `json:"controlId"`
		Enabled    *bool  `json:"enabled"`
		Parameters []struct {
			ID        string `json:"id"`
			Value     any    `json:"value"`
			MatchMode string `json:"matchMode"`
		} `json:"parameters"`
	} `json:"controls"`
	Templates []struct {
		ID         string            `json:"id"`
		ControlID  string            `json:"controlId"`
		Values     map[string]any    `json:"values"`
		MatchModes map[string]string `json:"matchModes"`
	} `json:"templates"`
	Agents map[string]struct {
		TypeOverride string `json:"typeOverride"`
		DetectedType string `json:"detectedType"`
		Controls     map[string]struct {
			TemplateID string            `json:"templateId"`
			Parameters map[string]any    `json:"parameters"`
			MatchModes map[string]string `json:"matchModes"`
		} `json:"controls"`
	} `json:"agents"`
}

// NoTemplate is the plugin's explicit "no template" assignment.
const NoTemplate = "none"

// systemTypes are the system types the plugin knows; any other value is ignored.
var systemTypes = map[string]bool{"linux": true, "zimbra-ldap": true, "windows": true, "manager": true}

// Level is the active ENS level (BAJO, MEDIO, ALTO); "" when not set.
func (c *Config) Level() string {
	return c.Global.EnsLevel
}

// ControlEnabled: false only when the configuration disables the control.
func (c *Config) ControlEnabled(controlID string) bool {
	for _, control := range c.Controls {
		if control.ControlID == controlID {
			return control.Enabled == nil || *control.Enabled
		}
	}
	return true
}

// Load reads the ACTIVE_CONFIGURATION document of index (usually
// "wazuh-ens-configuration").
func Load(ctx context.Context, client *indexer.Client, index string) (*Config, error) {

	query := map[string]any{
		"size":  1,
		"query": map[string]any{"term": map[string]any{"documentType": "ACTIVE_CONFIGURATION"}},
	}

	var resp struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Configuration Config `json:"configuration"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := client.Search(ctx, index, query, &resp); err != nil {
		return nil, err
	}

	if len(resp.Hits.Hits) == 0 {
		return nil, fmt.Errorf("no ACTIVE_CONFIGURATION in %s", index)
	}

	return &resp.Hits.Hits[0].Source.Configuration, nil
}

// List returns a list parameter for one agent, resolved as valueAndMode. A
// parameter written as a regular expression is an error here: use Matcher.
func (c *Config) List(agentID, controlID, paramID string) ([]string, error) {

	value, mode, ok := c.valueAndMode(agentID, controlID, paramID)

	if !ok {
		return nil, ErrNotSet
	}

	if mode == "regex" {
		return nil, fmt.Errorf("%s %s is a regular expression, which this evidence does not accept", controlID, paramID)
	}

	return listValue(value)
}

// Number returns a numeric parameter for one agent (agent value first, then
// the control's). The plugin stores numbers as JSON numbers or as strings.
func (c *Config) Number(agentID, controlID, paramID string) (float64, error) {
	value, _, ok := c.valueAndMode(agentID, controlID, paramID)
	return number(value, ok)
}

// Bool returns a yes/no parameter: a JSON boolean, or the words the plugin
// screens use (sí/si/yes/true, no/false).
func (c *Config) Bool(agentID, controlID, paramID string) (bool, error) {

	value, _, ok := c.valueAndMode(agentID, controlID, paramID)
	if !ok || value == nil {
		return false, ErrNotSet
	}

	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "":
			return false, ErrNotSet
		case "sí", "si", "yes", "true":
			return true, nil
		case "no", "false":
			return false, nil
		}
		return false, fmt.Errorf("%q is not yes or no", v)
	}

	return false, fmt.Errorf("value of type %T is not yes or no", value)
}

func number(value any, ok bool) (float64, error) {

	if !ok {
		return 0, ErrNotSet
	}

	switch v := value.(type) {
	case float64:
		return v, nil
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, ErrNotSet
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a number", v)
		}
		return n, nil
	case nil:
		return 0, ErrNotSet
	default:
		return 0, fmt.Errorf("value of type %T is not a number", value)
	}
}

// ListColumn returns one column of a table parameter, whose rows are written
// "a | b | c" (P-07 is "usuario | sistema | rol"). col counts from 0. Rows
// with an empty cell in that column are skipped; ErrNotSet when none is left.
func (c *Config) ListColumn(agentID, controlID, paramID string, col int) ([]string, error) {
	return column(c, agentID, controlID, paramID, col)
}

func column(l Lister, agentID, controlID, paramID string, col int) ([]string, error) {

	rows, err := l.List(agentID, controlID, paramID)

	if err != nil {
		return nil, err
	}

	var values []string

	for _, row := range rows {

		cells := strings.Split(row, "|")

		if col >= len(cells) {
			continue
		}

		if cell := strings.TrimSpace(cells[col]); cell != "" {
			values = append(values, cell)
		}
	}

	if len(values) == 0 {
		return nil, ErrNotSet
	}

	return values, nil
}

// MaxPatternLength is the plugin's limit for a regular expression parameter.
const MaxPatternLength = 512

// Matcher answers "is this name in the parameter?" for a list parameter that
// the plugin lets the auditor write either as a list or as one regular
// expression (matchMode "regex").
type Matcher struct {
	list    []string
	pattern *regexp.Regexp
	source  string
}

// ListMatcher builds a Matcher from a plain list.
func ListMatcher(values ...string) Matcher {
	return Matcher{list: values}
}

// PatternMatcher builds a Matcher from a regular expression, with the same
// checks as a configured one.
func PatternMatcher(source string) (Matcher, error) {

	if source != strings.TrimSpace(source) {
		return Matcher{}, fmt.Errorf("regular expression %q starts or ends with spaces", source)
	}
	if len(source) > MaxPatternLength {
		return Matcher{}, fmt.Errorf("regular expression longer than %d characters", MaxPatternLength)
	}

	// Anchored here: the plugin requires a full match.
	pattern, err := regexp.Compile(`^(?:` + source + `)$`)
	if err != nil {
		return Matcher{}, fmt.Errorf("regular expression %q: %w", source, err)
	}

	return Matcher{pattern: pattern, source: source}, nil
}

// Match: a list compares ignoring case, as the plugin does for forbidden
// lists; a pattern must match the whole name (RE2, as the plugin).
func (m Matcher) Match(name string) bool {

	if m.pattern != nil {
		return m.pattern.MatchString(name)
	}

	for _, entry := range m.list {
		if strings.EqualFold(entry, name) {
			return true
		}
	}

	return false
}

// String describes the parameter for a verdict reason.
func (m Matcher) String() string {
	if m.pattern != nil {
		return "pattern " + m.source
	}
	return strings.Join(m.list, ", ")
}

// Matcher returns a list-or-pattern parameter for one agent, resolved as
// valueAndMode.
func (c *Config) Matcher(agentID, controlID, paramID string) (Matcher, error) {

	value, mode, ok := c.valueAndMode(agentID, controlID, paramID)

	if !ok {
		return Matcher{}, ErrNotSet
	}

	if mode != "regex" {
		list, err := listValue(value)
		return Matcher{list: list}, err
	}

	source, isString := value.(string)
	if !isString || strings.TrimSpace(source) == "" {
		return Matcher{}, ErrNotSet
	}

	return PatternMatcher(source)
}

// valueAndMode resolves a parameter for one agent as the plugin does
// (configuration-resolver.ts), with the match mode stored at the level the
// value comes from:
//
//  1. Organisation parameters (and those the catalog does not know): the
//     control's common value only; an agent value is ignored.
//  2. System and platform parameters: the agent's own value; else its
//     template (the assigned one, built-in or custom; NoTemplate disables;
//     with none assigned or found, the built-in default of its system type);
//     else the common value.
//
// Union parameters (read whole across agents) do not occur in op.acc.1 and
// are not resolved here.
func (c *Config) valueAndMode(agentID, controlID, paramID string) (any, string, bool) {

	if catalog.IsAgentLevel(controlID, paramID) {

		agent, hasProfile := c.Agents[agentID]
		entry := agent.Controls[controlID]

		if hasProfile {
			if value, ok := entry.Parameters[paramID]; ok {
				return value, entry.MatchModes[paramID], true
			}
		}

		if values, modes, ok := c.template(agent.TypeOverride, agent.DetectedType, entry.TemplateID, controlID); ok {
			if value, ok := values[paramID]; ok {
				return value, modes[paramID], true
			}
		}
	}

	for _, control := range c.Controls {
		if control.ControlID != controlID {
			continue
		}
		for _, p := range control.Parameters {
			if p.ID == paramID {
				return p.Value, p.MatchMode, true
			}
		}
	}

	return nil, "", false
}

// template finds the values of the agent's effective template for a control.
func (c *Config) template(typeOverride, detectedType, assigned, controlID string) (map[string]any, map[string]string, bool) {

	if assigned == NoTemplate {
		return nil, nil, false
	}

	if assigned != "" {
		if t, ok := catalog.BuiltinTemplate(assigned, controlID); ok {
			return t.Values[controlID], t.MatchModes[controlID], true
		}
		for _, t := range c.Templates {
			if t.ID == assigned && t.ControlID == controlID {
				return t.Values, t.MatchModes, true
			}
		}
	}

	systemType := typeOverride
	if !systemTypes[systemType] {
		systemType = detectedType
	}
	if !systemTypes[systemType] {
		return nil, nil, false
	}

	if t, ok := catalog.TypeDefaultTemplate(controlID, systemType); ok {
		return t.Values[controlID], t.MatchModes[controlID], true
	}

	return nil, nil, false
}

// listValue accepts a JSON list of strings or one string with one entry per
// line, drops empty entries, and fails with ErrNotSet when nothing is left.
func listValue(value any) ([]string, error) {

	var raw []string

	switch v := value.(type) {
	case []any:
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("list entry %v is not a string", item)
			}
			raw = append(raw, s)
		}
	case string:
		raw = strings.Split(v, "\n")
	case nil:
		return nil, ErrNotSet
	default:
		return nil, fmt.Errorf("value of type %T is not a list", value)
	}

	var values []string

	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			values = append(values, s)
		}
	}

	if len(values) == 0 {
		return nil, ErrNotSet
	}

	return values, nil
}

// Lister is anything that answers List and ListColumn: a loaded *Config, or
// Unavailable.
type Lister interface {
	List(agentID, controlID, paramID string) ([]string, error)
	ListColumn(agentID, controlID, paramID string, col int) ([]string, error)
	Number(agentID, controlID, paramID string) (float64, error)
	Bool(agentID, controlID, paramID string) (bool, error)
	Matcher(agentID, controlID, paramID string) (Matcher, error)
	Level() string
	ControlEnabled(controlID string) bool
}

// Unavailable answers every List with err: used when the configuration could
// not be loaded, so every parameter-based evidence says why.
func Unavailable(err error) Lister {
	return unavailable{err}
}

type unavailable struct{ err error }

func (u unavailable) List(string, string, string) ([]string, error) {
	return nil, fmt.Errorf("configuration not loaded: %w", u.err)
}

func (u unavailable) ListColumn(agentID, controlID, paramID string, _ int) ([]string, error) {
	return u.List(agentID, controlID, paramID)
}

func (u unavailable) Number(string, string, string) (float64, error) {
	return 0, fmt.Errorf("configuration not loaded: %w", u.err)
}

func (u unavailable) Bool(string, string, string) (bool, error) {
	return false, fmt.Errorf("configuration not loaded: %w", u.err)
}

func (u unavailable) Matcher(string, string, string) (Matcher, error) {
	return Matcher{}, fmt.Errorf("configuration not loaded: %w", u.err)
}

// Without a configuration the level is not known: nothing is ruled out.
func (u unavailable) Level() string { return "" }

func (u unavailable) ControlEnabled(string) bool { return true }

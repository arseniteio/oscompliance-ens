package params

import (
	"context"

	"errors"
	"fmt"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"regexp"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/indexer"
)

var ErrNotSet = errors.New("not set")

type Config struct {
	Global struct {
		EnsLevel string `json:"ensLevel"`
	} `json:"global"`
	Scope struct {
		Mode     string   `json:"mode"`
		GroupIDs []string `json:"groupIds"`
	} `json:"scope"`
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

const NoTemplate = "none"

var systemTypes = map[string]bool{"linux": true, "zimbra-ldap": true, "windows": true, "manager": true}

// Groups are the Wazuh groups of the ENS scope; a scope by agent or the whole fleet names none.
func (c *Config) Groups() []string {
	if c.Scope.Mode != "group" {
		return nil
	}
	return c.Scope.GroupIDs
}

func (c *Config) Level() string {
	return c.Global.EnsLevel
}

func (c *Config) ControlEnabled(controlID string) bool {
	for _, control := range c.Controls {
		if control.ControlID == controlID {
			return control.Enabled == nil || *control.Enabled
		}
	}
	return true
}

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

func (c *Config) Number(agentID, controlID, paramID string) (float64, error) {
	value, _, ok := c.valueAndMode(agentID, controlID, paramID)
	return number(value, ok)
}

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

const MaxPatternLength = 512

type Matcher struct {
	list    []string
	pattern *regexp.Regexp
	source  string
}

func ListMatcher(values ...string) Matcher {
	return Matcher{list: values}
}

func PatternMatcher(source string) (Matcher, error) {

	if source != strings.TrimSpace(source) {
		return Matcher{}, fmt.Errorf("regular expression %q starts or ends with spaces", source)
	}
	if len(source) > MaxPatternLength {
		return Matcher{}, fmt.Errorf("regular expression longer than %d characters", MaxPatternLength)
	}

	pattern, err := regexp.Compile(`^(?:` + source + `)$`)
	if err != nil {
		return Matcher{}, fmt.Errorf("regular expression %q: %w", source, err)
	}

	return Matcher{pattern: pattern, source: source}, nil
}

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

func (m Matcher) String() string {
	if m.pattern != nil {
		return "pattern " + m.source
	}
	return strings.Join(m.list, ", ")
}

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

type Lister interface {
	List(agentID, controlID, paramID string) ([]string, error)
	ListColumn(agentID, controlID, paramID string, col int) ([]string, error)
	Number(agentID, controlID, paramID string) (float64, error)
	Bool(agentID, controlID, paramID string) (bool, error)
	Matcher(agentID, controlID, paramID string) (Matcher, error)
	Level() string
	ControlEnabled(controlID string) bool
}

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

func (u unavailable) Level() string { return "" }

func (u unavailable) ControlEnabled(string) bool { return true }

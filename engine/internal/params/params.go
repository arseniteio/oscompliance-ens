package params

import (
	"context"

	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"

	"github.com/arseniteio/oscompliance-ens/engine/internal/indexer"
)

var ErrNotSet = errors.New("not set")

// ValueError says why a parameter value cannot be used, in words the reasons can translate.
type ValueError struct{ Message catalog.Message }

func (e ValueError) Error() string { return e.Message.Render("en") }

func invalid(code string, pairs ...any) error { return ValueError{catalog.Says(code, pairs...)} }

type Config struct {
	Global struct {
		EnsLevel string `json:"ensLevel"`
	} `json:"global"`
	Scope struct {
		Mode     string   `json:"mode"`
		AgentIDs []string `json:"agentIds"`
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

	inventoryTypes map[string]string
}

const NoTemplate = "none"

// UseInventoryTypes gives each machine the system type its inventory platform says. It wins over the type
// the configuration stored, so a new machine gets the template of its type without anyone saving it.
func (c *Config) UseInventoryTypes(platforms map[string]string) {
	c.inventoryTypes = map[string]string{}
	for agentID, platform := range platforms {
		if t := catalog.SystemTypeOf(agentID, platform); t != "" {
			c.inventoryTypes[agentID] = t
		}
	}
}

func (c *Config) systemType(agentID, stored string) string {
	if t, ok := c.inventoryTypes[agentID]; ok {
		return t
	}
	return stored
}

var systemTypes = map[string]bool{"linux": true, "windows": true, "manager": true}

// Groups are the Wazuh groups of the ENS scope; a scope by agent or the whole fleet names none.
func (c *Config) Groups() []string {
	if c.Scope.Mode != "group" {
		return nil
	}
	return c.Scope.GroupIDs
}

// Evaluates tells whether a machine is in the ENS scope, as the plugin resolves it. The manager is in no group
// and is always in.
func (c *Config) Evaluates(agentID string, groups []string) bool {
	if agentID == "000" {
		return true
	}
	switch c.Scope.Mode {
	case "group":
		return slices.ContainsFunc(groups, func(g string) bool {
			return slices.ContainsFunc(c.Scope.GroupIDs, func(in string) bool {
				return strings.EqualFold(strings.TrimSpace(in), strings.TrimSpace(g))
			})
		})
	case "agent":
		return slices.ContainsFunc(c.Scope.AgentIDs, func(in string) bool { return strings.TrimSpace(in) == agentID })
	}
	return true
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
		return nil, invalid("param.is_regex")
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
		return false, invalid("param.not_yes_no", "value", v)
	}

	return false, invalid("param.not_yes_no", "value", fmt.Sprint(value))
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
			return 0, invalid("param.not_number", "value", v)
		}
		return n, nil
	case nil:
		return 0, ErrNotSet
	default:
		return 0, invalid("param.not_number", "value", fmt.Sprint(value))
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
		return Matcher{}, invalid("param.regex_spaces", "value", source)
	}
	if len(source) > MaxPatternLength {
		return Matcher{}, invalid("param.regex_long", "max", MaxPatternLength)
	}

	pattern, err := regexp.Compile(`^(?:` + source + `)$`)
	if err != nil {
		return Matcher{}, invalid("param.regex_invalid", "value", source, "error", err.Error())
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

		if values, modes, ok := c.template(agent.TypeOverride, c.systemType(agentID, agent.DetectedType), entry.TemplateID, controlID); ok {
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
				return nil, invalid("param.not_text", "value", fmt.Sprint(item))
			}
			raw = append(raw, s)
		}
	case string:
		raw = strings.Split(v, "\n")
	case nil:
		return nil, ErrNotSet
	default:
		return nil, invalid("param.not_list", "value", fmt.Sprint(value))
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
	return nil, invalid("param.not_loaded", "error", u.err.Error())
}

func (u unavailable) ListColumn(agentID, controlID, paramID string, _ int) ([]string, error) {
	return u.List(agentID, controlID, paramID)
}

func (u unavailable) Number(string, string, string) (float64, error) {
	return 0, invalid("param.not_loaded", "error", u.err.Error())
}

func (u unavailable) Bool(string, string, string) (bool, error) {
	return false, invalid("param.not_loaded", "error", u.err.Error())
}

func (u unavailable) Matcher(string, string, string) (Matcher, error) {
	return Matcher{}, invalid("param.not_loaded", "error", u.err.Error())
}

func (u unavailable) Level() string { return "" }

func (u unavailable) ControlEnabled(string) bool { return true }

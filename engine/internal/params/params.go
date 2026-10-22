// Package params reads policy parameters from the plugin's configuration
// index, so each parameter lives in one place: the Configuration screen.
package params

import (
	"context"
	"errors"
	"fmt"
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
	Controls []struct {
		ControlID  string `json:"controlId"`
		Parameters []struct {
			ID        string `json:"id"`
			Value     any    `json:"value"`
			MatchMode string `json:"matchMode"`
		} `json:"parameters"`
	} `json:"controls"`
	Agents map[string]struct {
		Controls map[string]struct {
			Parameters map[string]any `json:"parameters"`
		} `json:"controls"`
	} `json:"agents"`
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

// List returns a list parameter for one agent: the agent's own value when it
// has one, otherwise the control's. Plugin templates are not applied yet.
func (c *Config) List(agentID, controlID, paramID string) ([]string, error) {

	if agent, ok := c.Agents[agentID]; ok {
		if value, ok := agent.Controls[controlID].Parameters[paramID]; ok {
			return listValue(value)
		}
	}

	for _, control := range c.Controls {

		if control.ControlID != controlID {
			continue
		}

		for _, p := range control.Parameters {

			if p.ID != paramID {
				continue
			}

			if p.MatchMode == "regex" {
				return nil, fmt.Errorf("%s %s uses a regular expression, not supported by the engine yet", controlID, paramID)
			}

			return listValue(p.Value)
		}
	}

	return nil, ErrNotSet
}

// Number returns a numeric parameter for one agent (agent value first, then
// the control's). The plugin stores numbers as JSON numbers or as strings.
func (c *Config) Number(agentID, controlID, paramID string) (float64, error) {
	return number(c.value(agentID, controlID, paramID))
}

// value finds the raw value of a parameter: the agent's own, else the
// control's. ok is false when neither exists.
func (c *Config) value(agentID, controlID, paramID string) (any, bool) {

	if agent, ok := c.Agents[agentID]; ok {
		if value, ok := agent.Controls[controlID].Parameters[paramID]; ok {
			return value, true
		}
	}

	for _, control := range c.Controls {
		if control.ControlID != controlID {
			continue
		}
		for _, p := range control.Parameters {
			if p.ID == paramID {
				return p.Value, true
			}
		}
	}

	return nil, false
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

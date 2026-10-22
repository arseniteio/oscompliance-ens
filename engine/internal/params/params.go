// Package params reads policy parameters from the plugin's configuration
// index, so each parameter lives in one place: the Configuration screen.
package params

import (
	"context"
	"errors"
	"fmt"
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

// Lister is anything that answers List: a loaded *Config, or Unavailable.
type Lister interface {
	List(agentID, controlID, paramID string) ([]string, error)
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

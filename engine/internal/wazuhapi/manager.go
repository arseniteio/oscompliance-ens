package wazuhapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

func (c *Client) ManagerStatus(ctx context.Context) (map[string]string, error) {
	var status []map[string]string
	if _, err := c.items(ctx, "/manager/status", 0, 0, &status); err != nil {
		return nil, err
	}
	if len(status) == 0 {
		return map[string]string{}, nil
	}
	return status[0], nil
}

// ManagerSection decodes one section of the manager's ossec.conf into v; a section the file lacks leaves
// v untouched and returns false.
func (c *Client) ManagerSection(ctx context.Context, section string, v any) (bool, error) {
	var items []map[string]json.RawMessage
	if _, err := c.items(ctx, "/manager/configuration?section="+url.QueryEscape(section), 0, 0, &items); err != nil {
		return false, err
	}
	if len(items) == 0 {
		return false, nil
	}
	raw, ok := items[0][section]
	if !ok {
		return false, nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return false, fmt.Errorf("wazuh api: section %s: %w", section, err)
	}
	return true, nil
}

type Rule struct {
	ID      int            `json:"id"`
	Level   int            `json:"level"`
	File    string         `json:"filename"`
	Dir     string         `json:"relative_dirname"`
	Groups  []string       `json:"groups"`
	Mitre   []string       `json:"mitre"`
	Details map[string]any `json:"details"`
}

const rulesPage = 1000

// Rules are the rules the manager loads, the excluded files left out.
func (c *Client) Rules(ctx context.Context) ([]Rule, error) {
	var out []Rule
	for offset := 0; ; offset += rulesPage {
		var page []Rule
		total, err := c.items(ctx, "/rules?status=enabled&select=id,level,filename,relative_dirname,groups,mitre,details", rulesPage, offset, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < rulesPage || len(out) >= total {
			return out, nil
		}
	}
}

type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	InstallTime string `json:"install_time"`
}

func (c *Client) AgentPackage(ctx context.Context, agentID, name string) (*Package, error) {
	var found []Package
	path := "/syscollector/" + url.PathEscape(agentID) + "/packages?select=name,version,install_time&name=" + url.QueryEscape(name)
	if _, err := c.items(ctx, path, 1, 0, &found); err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, nil
	}
	return &found[0], nil
}

package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/indexer"
)

var historyMapping = map[string]any{
	"settings": map[string]any{"index": map[string]any{"auto_expand_replicas": "0-1"}},
	"mappings": map[string]any{
		"dynamic": "strict",
		"properties": map[string]any{
			"agent_id":          kw(),
			"agent_name":        kw(),
			"account_name":      kw(),
			"uid":               map[string]any{"type": "long"},
			"first_seen":        date(),
			"last_seen":         date(),
			"last_run_id":       kw(),
			"account_expires":   kw(),
			"disabled_since":    date(),
			"disabled_observed": map[string]any{"type": "boolean"},
			"deleted_at":        date(),
		},
	},
}

// maxAccounts bounds one agent's history read: far above any real host.
const maxAccounts = 10000

// History reads and writes the per-account history (one document per agent
// and account).
type History struct {
	client *indexer.Client
	index  string
}

// NewHistory creates index if needed and returns a store for it.
func NewHistory(ctx context.Context, client *indexer.Client, index string) (*History, error) {

	if err := client.EnsureIndex(ctx, index, historyMapping); err != nil {
		return nil, err
	}

	return &History{client: client, index: index}, nil
}

// Load returns the history of one agent by account name.
func (h *History) Load(ctx context.Context, agentID string) (map[string]history.Account, error) {

	query := map[string]any{
		"size":  maxAccounts,
		"query": map[string]any{"term": map[string]any{"agent_id": agentID}},
	}

	var resp struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := h.client.Search(ctx, h.index, query, &resp); err != nil {
		return nil, err
	}

	accounts := map[string]history.Account{}

	for _, hit := range resp.Hits.Hits {
		var a history.Account
		if err := json.Unmarshal(hit.Source, &a); err != nil {
			return nil, err
		}
		accounts[a.AccountName] = a
	}

	return accounts, nil
}

// Save writes each account under agent/account, replacing the earlier version.
func (h *History) Save(ctx context.Context, accounts []history.Account) error {

	for _, a := range accounts {
		if err := h.client.Put(ctx, h.index, strings.Join([]string{a.AgentID, a.AccountName}, "/"), a); err != nil {
			return err
		}
	}

	return nil
}

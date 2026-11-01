package store

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"strings"
	"sync"

	"github.com/arseniteio/oscompliance-ens/engine/internal/batch"
	"github.com/arseniteio/oscompliance-ens/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
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
			"state_unknown":     map[string]any{"type": "boolean"},
			"deleted_at":        date(),
		},
	},
}

type History struct {
	client  *indexer.Client
	index   string
	plan    batch.Plan
	mu      sync.Mutex
	pending []history.Account
	written bool
}

func NewHistory(ctx context.Context, client *indexer.Client, index string) (*History, error) {

	if err := client.EnsureIndex(ctx, index, historyMapping); err != nil {
		return nil, err
	}

	return &History{client: client, index: index}, nil
}

func (h *History) Plan(agents []verdict.Agent) {
	ids := make([]string, len(agents))
	for i, a := range agents {
		ids[i] = a.ID
	}
	h.plan.Set(ids)
}

const historyKey = "history"

func (h *History) Load(ctx context.Context, agentID string) (map[string]history.Account, error) {
	accounts, err := batch.Get(ctx, &h.plan, historyKey, agentID, h.load)
	return maps.Clone(accounts), err
}

func (h *History) load(ctx context.Context, ids []string) (map[string]map[string]history.Account, error) {

	if err := h.Flush(ctx); err != nil {
		return nil, err
	}

	out := map[string]map[string]history.Account{}
	for _, id := range ids {
		out[id] = map[string]history.Account{}
	}

	var after []any

	for {
		query := map[string]any{
			"size":  pageSize,
			"query": map[string]any{"terms": map[string]any{"agent_id": ids}},
			"sort":  []any{map[string]any{"agent_id": "asc"}, map[string]any{"account_name": "asc"}},
		}
		if after != nil {
			query["search_after"] = after
		}

		var resp struct {
			Hits struct {
				Hits []struct {
					Sort   []any           `json:"sort"`
					Source json.RawMessage `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}

		if err := h.client.Search(ctx, h.index, query, &resp); err != nil {
			return nil, err
		}

		for _, hit := range resp.Hits.Hits {
			var a history.Account
			if err := json.Unmarshal(hit.Source, &a); err != nil {
				return nil, err
			}
			if out[a.AgentID] == nil {
				out[a.AgentID] = map[string]history.Account{}
			}
			out[a.AgentID][a.AccountName] = a
		}

		if len(resp.Hits.Hits) < pageSize {
			return out, nil
		}
		after = resp.Hits.Hits[len(resp.Hits.Hits)-1].Sort
	}
}

const pageSize = 1000

func (h *History) Save(ctx context.Context, accounts []history.Account) error {

	for _, a := range accounts {
		batch.Update(ctx, &h.plan, historyKey, a.AgentID, func(m map[string]history.Account) map[string]history.Account {
			if m == nil {
				m = map[string]history.Account{}
			}
			m[a.AccountName] = a
			return m
		})
	}

	h.mu.Lock()
	h.pending = append(h.pending, accounts...)
	full := len(h.pending) >= bulkSize
	h.mu.Unlock()

	if full {
		return h.send(ctx)
	}
	return nil
}

func (h *History) send(ctx context.Context) error {

	h.mu.Lock()
	pending := h.pending
	h.pending = nil
	if len(pending) > 0 {
		h.written = true
	}
	h.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}

	var body bytes.Buffer
	for _, a := range pending {
		action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": h.index, "_id": strings.Join([]string{a.AgentID, a.AccountName}, "/")}})
		doc, err := json.Marshal(a)
		if err != nil {
			return err
		}
		body.Write(action)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
	}

	return h.client.Bulk(ctx, body.Bytes())
}

func (h *History) Flush(ctx context.Context) error {

	if err := h.send(ctx); err != nil {
		return err
	}

	h.mu.Lock()
	written := h.written
	h.written = false
	h.mu.Unlock()

	if !written {
		return nil
	}
	return h.client.Refresh(ctx, h.index)
}

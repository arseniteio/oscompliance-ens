package store

import (
	"context"
	"fmt"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/groupconf"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/indexer"
)

var configHistoryMapping = map[string]any{
	"settings": map[string]any{"index": map[string]any{"auto_expand_replicas": "0-1"}},
	"mappings": map[string]any{
		"dynamic": "strict",
		"properties": map[string]any{
			"group":      kw(),
			"@timestamp": date(),
			"applied":    map[string]any{"type": "boolean"},
			"before":     map[string]any{"type": "text", "index": false},
			"after":      map[string]any{"type": "text", "index": false},
			"agents":     map[string]any{"type": "integer"},
		},
	},
}

type ConfigHistory struct {
	client *indexer.Client
	index  string
}

func NewConfigHistory(ctx context.Context, client *indexer.Client, index string) (*ConfigHistory, error) {

	if err := client.EnsureIndex(ctx, index, configHistoryMapping); err != nil {
		return nil, err
	}

	return &ConfigHistory{client: client, index: index}, nil
}

func (h *ConfigHistory) Write(ctx context.Context, c groupconf.Change) error {
	return h.client.Put(ctx, h.index, fmt.Sprintf("%s/%d", c.Group, c.At.UnixMilli()), c)
}

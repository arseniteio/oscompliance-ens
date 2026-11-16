package store

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/hostprofile"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

var hostProfileMapping = map[string]any{
	"settings": map[string]any{"index": map[string]any{"auto_expand_replicas": "0-1"}},
	"mappings": map[string]any{
		"dynamic": "strict",
		"properties": map[string]any{
			"@timestamp": date(),
			"agent": map[string]any{"properties": map[string]any{
				"id":   kw(),
				"name": kw(),
			}},
			"hostname": kw(),
			"groups":   kw(),
			"os": map[string]any{"properties": map[string]any{
				"name":         kw(),
				"version":      kw(),
				"platform":     kw(),
				"architecture": kw(),
			}},
			"distro":   kw(),
			"family":   kw(),
			"role":     kw(),
			"services": kw(),
			"signals": map[string]any{"properties": map[string]any{
				"field": kw(),
				"value": kw(),
				"from":  kw(),
			}},
			"engine_version": kw(),
		},
	},
}

type HostProfiles struct {
	client *indexer.Client
	index  string
}

func NewHostProfiles(ctx context.Context, client *indexer.Client, index string) (*HostProfiles, error) {

	if err := client.EnsureIndex(ctx, index, hostProfileMapping); err != nil {
		return nil, err
	}
	if err := client.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_mapping", hostProfileMapping["mappings"], nil); err != nil {
		return nil, err
	}

	return &HostProfiles{client: client, index: index}, nil
}

func (h *HostProfiles) Write(ctx context.Context, profiles []hostprofile.Profile) error {

	for start := 0; start < len(profiles); start += bulkSize {

		var body bytes.Buffer
		for _, p := range profiles[start:min(start+bulkSize, len(profiles))] {
			action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": h.index, "_id": p.Agent.ID}})
			doc, err := json.Marshal(p)
			if err != nil {
				return err
			}
			body.Write(action)
			body.WriteByte('\n')
			body.Write(doc)
			body.WriteByte('\n')
		}

		if err := h.client.Bulk(ctx, body.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

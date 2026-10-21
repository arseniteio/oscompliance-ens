// Package store writes verdicts to their own index.
package store

import (
	"context"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/indexer"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// mapping is strict: a field the engine does not know is a bug, not data.
var mapping = map[string]any{
	"settings": map[string]any{"index": map[string]any{"auto_expand_replicas": "0-1"}},
	"mappings": map[string]any{
		"dynamic": "strict",
		"properties": map[string]any{
			"oscompliance_verdict": kw(),
			"@timestamp":           date(),
			"control":              kw(),
			"evidence":             kw(),
			"agent": map[string]any{"properties": map[string]any{
				"id":   kw(),
				"name": kw(),
			}},
			"status":         kw(),
			"cause":          kw(),
			"reason":         map[string]any{"type": "keyword", "ignore_above": 2048},
			"run_id":         kw(),
			"window_start":   date(),
			"window_end":     date(),
			"engine_version": kw(),
		},
	},
}

func kw() map[string]any   { return map[string]any{"type": "keyword"} }
func date() map[string]any { return map[string]any{"type": "date"} }

// Verdicts writes to one index.
type Verdicts struct {
	client *indexer.Client
	index  string
}

// NewVerdicts creates index if needed and returns a writer for it.
func NewVerdicts(ctx context.Context, client *indexer.Client, index string) (*Verdicts, error) {

	if err := client.EnsureIndex(ctx, index, mapping); err != nil {
		return nil, err
	}

	return &Verdicts{client: client, index: index}, nil
}

// Write stores v. The document ID is agent, control, evidence and the pass
// judged, so judging the same pass again replaces the verdict instead of
// adding one.
func (s *Verdicts) Write(ctx context.Context, v verdict.Verdict) error {

	pass := v.RunID
	if pass == "" {
		pass = "none"
	}

	id := strings.Join([]string{v.Agent.ID, v.Control, v.Evidence, pass}, "/")

	return s.client.Put(ctx, s.index, id, v)
}

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
			"scope":                kw(),
			"control":              kw(),
			"requirement":          kw(),
			"evidence":             kw(),
			"agent": map[string]any{"properties": map[string]any{
				"id":   kw(),
				"name": kw(),
			}},
			"status":                  kw(),
			"cause":                   kw(),
			"reason":                  map[string]any{"type": "keyword", "ignore_above": 2048},
			"run_id":                  kw(),
			"window_start":            date(),
			"window_end":              date(),
			"engine_version":          kw(),
			"evidenced":               map[string]any{"type": "boolean"},
			"attested":                map[string]any{"type": "boolean"},
			"score":                   map[string]any{"type": "integer"},
			"coverage":                map[string]any{"type": "integer"},
			"applicable_requirements": map[string]any{"type": "integer"},
			"measured_requirements":   map[string]any{"type": "integer"},
			"unmeasured_requirements": kw(),
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

// Write stores v under an ID that replaces instead of piling up:
//
//   - evidence: agent/control/evidence/run_id ("none" without a pass), so
//     judging the same pass again replaces it and each pass stays as history;
//   - requirement: agent/control/requirement/day, and control:
//     agent/control/day: the last verdict of each day, one point per day of
//     the evolution series.
func (s *Verdicts) Write(ctx context.Context, v verdict.Verdict) error {
	return s.client.Put(ctx, s.index, DocumentID(v), v)
}

// DocumentID is the document ID Write uses for v.
func DocumentID(v verdict.Verdict) string {

	day := v.Timestamp
	if len(day) >= 10 {
		day = day[:10]
	}

	switch v.Scope {
	case verdict.ScopeRequirement:
		return strings.Join([]string{v.Agent.ID, v.Control, v.Requirement, day}, "/")
	case verdict.ScopeControl:
		return strings.Join([]string{v.Agent.ID, v.Control, day}, "/")
	}

	pass := v.RunID
	if pass == "" {
		pass = "none"
	}

	return strings.Join([]string{v.Agent.ID, v.Control, v.Evidence, pass}, "/")
}

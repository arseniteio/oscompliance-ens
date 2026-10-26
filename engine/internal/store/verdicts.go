// Package store writes verdicts to their own index.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/indexer"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
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
	client  *indexer.Client
	index   string
	pending []verdict.Verdict
}

// bulkSize is how many verdicts go in one bulk request: a pass writes
// about 120 per agent, one request each would not scale to a large fleet.
const bulkSize = 500

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
//
// Verdicts are sent in bulk: Flush sends what is left at the end of a pass.
func (s *Verdicts) Write(ctx context.Context, v verdict.Verdict) error {

	s.pending = append(s.pending, v)
	if len(s.pending) < bulkSize {
		return nil
	}

	return s.Flush(ctx)
}

// Flush sends the pending verdicts.
func (s *Verdicts) Flush(ctx context.Context) error {

	if len(s.pending) == 0 {
		return nil
	}

	var body bytes.Buffer
	for _, v := range s.pending {
		action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": s.index, "_id": DocumentID(v)}})
		doc, err := json.Marshal(v)
		if err != nil {
			return err
		}
		body.Write(action)
		body.WriteByte('\n')
		body.Write(doc)
		body.WriteByte('\n')
	}

	s.pending = s.pending[:0]
	return s.client.Bulk(ctx, body.Bytes())
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

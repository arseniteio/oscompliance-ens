// Package source reads facts from the alerts index where Wazuh stores them.
package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/indexer"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// FactRule is the Wazuh rule every indexed fact matches (catalog/wazuh).
const FactRule = "119001"

// pageSize is the number of hits per page when paging through facts.
const pageSize = 1000

// maxAgents bounds the per-agent aggregations.
const maxAgents = 10000

// Source reads facts from one alerts index pattern.
type Source struct {
	client *indexer.Client
	index  string
}

// New returns a Source over index, usually "wazuh-alerts-*".
func New(client *indexer.Client, index string) *Source {
	return &Source{client: client, index: index}
}

type hit struct {
	ID     string          `json:"_id"`
	Sort   []any           `json:"sort"`
	Source json.RawMessage `json:"_source"`
}

type alert struct {
	Timestamp string         `json:"timestamp"`
	Agent     verdict.Agent  `json:"agent"`
	Data      map[string]any `json:"data"`
}

func factFilter(name string, since time.Time) []any {
	return []any{
		map[string]any{"term": map[string]any{"rule.id": FactRule}},
		map[string]any{"term": map[string]any{"data.fact": name}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
}

// Agents returns every agent that sent any fact since the given time.
func (s *Source) Agents(ctx context.Context, since time.Time) ([]verdict.Agent, error) {

	query := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"rule.id": FactRule}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": map[string]any{"agents": map[string]any{
			"terms": map[string]any{"field": "agent.id", "size": maxAgents},
			"aggs": map[string]any{"name": map[string]any{
				"terms": map[string]any{"field": "agent.name", "size": 1},
			}},
		}},
	}

	var resp struct {
		Aggregations struct {
			Agents struct {
				Buckets []struct {
					Key  string `json:"key"`
					Name struct {
						Buckets []struct {
							Key string `json:"key"`
						} `json:"buckets"`
					} `json:"name"`
				} `json:"buckets"`
			} `json:"agents"`
		} `json:"aggregations"`
	}

	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return nil, err
	}

	var agents []verdict.Agent

	for _, b := range resp.Aggregations.Agents.Buckets {
		a := verdict.Agent{ID: b.Key}
		if len(b.Name.Buckets) > 0 {
			a.Name = b.Name.Buckets[0].Key
		}
		agents = append(agents, a)
	}

	return agents, nil
}

// GroupSnapshots returns, per agent ID, the newest group_snapshot indexed
// since the given time.
func (s *Source) GroupSnapshots(ctx context.Context, since time.Time) (map[string]fact.GroupSnapshot, error) {

	newest, err := latestFacts[fact.GroupSnapshot](ctx, s, fact.GroupSnapshotFact, since, 1)

	if err != nil {
		return nil, err
	}

	snapshots := map[string]fact.GroupSnapshot{}

	for agentID, list := range newest {
		snapshots[agentID] = list[0]
	}

	return snapshots, nil
}

// GroupRecords returns every group_record of one pass of one agent.
func (s *Source) GroupRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.GroupRecord, error) {
	return passRecords[fact.GroupRecord](ctx, s, fact.GroupRecordFact, agentID, runID, since)
}

// IdentitySnapshots returns, per agent ID, up to n identity_snapshot facts
// indexed since the given time, newest first.
func (s *Source) IdentitySnapshots(ctx context.Context, since time.Time, n int) (map[string][]fact.IdentitySnapshot, error) {
	return latestFacts[fact.IdentitySnapshot](ctx, s, fact.IdentitySnapshotFact, since, n)
}

// latestFacts returns, per agent ID, up to n facts of type name, newest first.
func latestFacts[T any](ctx context.Context, s *Source, name string, since time.Time, n int) (map[string][]T, error) {

	query := map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": factFilter(name, since)}},
		"aggs": map[string]any{"agents": map[string]any{
			"terms": map[string]any{"field": "agent.id", "size": maxAgents},
			"aggs": map[string]any{"latest": map[string]any{
				"top_hits": map[string]any{"size": n, "sort": []any{map[string]any{"timestamp": "desc"}}},
			}},
		}},
	}

	var resp struct {
		Aggregations struct {
			Agents struct {
				Buckets []struct {
					Key    string `json:"key"`
					Latest struct {
						Hits struct {
							Hits []hit `json:"hits"`
						} `json:"hits"`
					} `json:"latest"`
				} `json:"buckets"`
			} `json:"agents"`
		} `json:"aggregations"`
	}

	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return nil, err
	}

	facts := map[string][]T{}

	for _, b := range resp.Aggregations.Agents.Buckets {
		for _, h := range b.Latest.Hits.Hits {
			var f T
			if err := decodeHit(h, &f); err != nil {
				return nil, fmt.Errorf("agent %s: %w", b.Key, err)
			}
			facts[b.Key] = append(facts[b.Key], f)
		}
	}

	return facts, nil
}

// IdentityRecords returns every identity_record of one pass of one agent.
func (s *Source) IdentityRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.IdentityRecord, error) {
	return passRecords[fact.IdentityRecord](ctx, s, fact.IdentityRecordFact, agentID, runID, since)
}

// passRecords reads every fact of type name with the given run_id from one
// agent, decoded into T. A Go method cannot have type parameters, so this is
// a function that takes the Source.
func passRecords[T any](ctx context.Context, s *Source, name, agentID, runID string, since time.Time) ([]T, error) {

	filter := append(factFilter(name, since),
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"data.run_id": runID}},
	)

	var records []T

	err := s.page(ctx, filter, func(h hit) error {
		var record T
		if err := decodeHit(h, &record); err != nil {
			return err
		}
		records = append(records, record)
		return nil
	})

	return records, err
}

// page walks every hit matching filter in timestamp order, with search_after
// so that the result size is not bounded by the indexer's result window.
func (s *Source) page(ctx context.Context, filter []any, fn func(hit) error) error {

	var after []any

	for {
		query := map[string]any{
			"size":  pageSize,
			"query": map[string]any{"bool": map[string]any{"filter": filter}},
			"sort":  []any{map[string]any{"timestamp": "asc"}, map[string]any{"id": "asc"}},
		}
		if after != nil {
			query["search_after"] = after
		}

		var resp struct {
			Hits struct {
				Hits []hit `json:"hits"`
			} `json:"hits"`
		}

		if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
			return err
		}

		for _, h := range resp.Hits.Hits {
			if err := fn(h); err != nil {
				return err
			}
		}

		if len(resp.Hits.Hits) < pageSize {
			return nil
		}

		after = resp.Hits.Hits[len(resp.Hits.Hits)-1].Sort
	}
}

func decodeHit(h hit, v any) error {

	var a alert

	if err := json.Unmarshal(h.Source, &a); err != nil {
		return fmt.Errorf("alert %s: %w", h.ID, err)
	}

	if err := Decode(a.Data, v); err != nil {
		return fmt.Errorf("alert %s: %w", h.ID, err)
	}

	return nil
}

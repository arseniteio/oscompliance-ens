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

// Source reads facts from one alerts index pattern, and the registered agents
// from Wazuh's monitoring index.
type Source struct {
	client     *indexer.Client
	index      string
	monitoring string
}

// New returns a Source over index (usually "wazuh-alerts-*") and monitoring
// (usually "wazuh-monitoring-*").
func New(client *indexer.Client, index, monitoring string) *Source {
	return &Source{client: client, index: index, monitoring: monitoring}
}

// ManagerID is the Wazuh manager's own agent ID. The monitoring index leaves
// it out, but the manager is audited like any other machine.
const ManagerID = "000"

// RegisteredAgents returns the agents Wazuh knows, whether or not they send
// facts: every agent of the monitoring index since the given time, plus the
// manager when it raised any alert in that time. An agent that went silent
// keeps getting verdicts (NOT_EVALUABLE by COLLECTION) instead of
// disappearing.
func (s *Source) RegisteredAgents(ctx context.Context, since time.Time) ([]verdict.Agent, error) {

	monitoring, err := s.agentNames(ctx, s.monitoring, "id", "name", []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})

	if err != nil {
		return nil, fmt.Errorf("monitoring: %w", err)
	}

	manager, err := s.agentNames(ctx, s.index, "agent.id", "agent.name", []any{
		map[string]any{"term": map[string]any{"agent.id": ManagerID}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})

	if err != nil {
		return nil, fmt.Errorf("manager: %w", err)
	}

	return append(monitoring, manager...), nil
}

// agentNames lists the distinct values of idField in index, each with the
// newest value of nameField.
func (s *Source) agentNames(ctx context.Context, index, idField, nameField string, filter []any) ([]verdict.Agent, error) {

	sub := map[string]any{"name": map[string]any{"terms": map[string]any{"field": nameField, "size": 1}}}

	var agents []verdict.Agent

	err := s.compositeIn(ctx, index, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": idField}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Name struct {
					Buckets []struct {
						Key string `json:"key"`
					} `json:"buckets"`
				} `json:"name"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			a := verdict.Agent{ID: keyString(key, "a")}
			if len(c.Name.Buckets) > 0 {
				a.Name = c.Name.Buckets[0].Key
			}
			agents = append(agents, a)
			return nil
		})

	return agents, err
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
	return s.agentNames(ctx, s.index, "agent.id", "agent.name", []any{
		map[string]any{"term": map[string]any{"rule.id": FactRule}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	})
}

// newest returns, per agent ID, the newest fact of type name since the given
// time.
func newest[T any](ctx context.Context, s *Source, name string, since time.Time) (map[string]T, error) {

	lists, err := latestFacts[T](ctx, s, name, since, 1)

	if err != nil {
		return nil, err
	}

	out := map[string]T{}

	for agentID, list := range lists {
		out[agentID] = list[0]
	}

	return out, nil
}

// SweepSnapshots returns, per agent, the newest file_sweep_snapshot.
func (s *Source) SweepSnapshots(ctx context.Context, since time.Time) (map[string]fact.FileSweepSnapshot, error) {
	return newest[fact.FileSweepSnapshot](ctx, s, fact.FileSweepSnapshotFact, since)
}

// SpecialFiles returns every special_file of one sweep of one agent.
func (s *Source) SpecialFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SpecialFile, error) {
	return passRecords[fact.SpecialFile](ctx, s, fact.SpecialFileFact, agentID, runID, since)
}

// UmaskSnapshots returns, per agent, the newest umask_snapshot.
func (s *Source) UmaskSnapshots(ctx context.Context, since time.Time) (map[string]fact.UmaskSnapshot, error) {
	return newest[fact.UmaskSnapshot](ctx, s, fact.UmaskSnapshotFact, since)
}

// SudoersSnapshots returns, per agent, the newest sudoers_snapshot.
func (s *Source) SudoersSnapshots(ctx context.Context, since time.Time) (map[string]fact.SudoersSnapshot, error) {
	return newest[fact.SudoersSnapshot](ctx, s, fact.SudoersSnapshotFact, since)
}

// SudoGrants returns every sudo_grant of one read of one agent.
func (s *Source) SudoGrants(ctx context.Context, agentID, runID string, since time.Time) ([]fact.SudoGrant, error) {
	return passRecords[fact.SudoGrant](ctx, s, fact.SudoGrantFact, agentID, runID, since)
}

// ConfigSnapshots returns, per agent, the newest config_snapshot.
func (s *Source) ConfigSnapshots(ctx context.Context, since time.Time) (map[string]fact.ConfigSnapshot, error) {
	return newest[fact.ConfigSnapshot](ctx, s, fact.ConfigSnapshotFact, since)
}

// ConfigFiles returns every config_file of one read of one agent.
func (s *Source) ConfigFiles(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ConfigFile, error) {
	return passRecords[fact.ConfigFile](ctx, s, fact.ConfigFileFact, agentID, runID, since)
}

// PAMSnapshots returns, per agent, the newest pam_snapshot.
func (s *Source) PAMSnapshots(ctx context.Context, since time.Time) (map[string]fact.PAMSnapshot, error) {
	return newest[fact.PAMSnapshot](ctx, s, fact.PAMSnapshotFact, since)
}

// PAMRules returns every pam_rule of one read of one agent.
func (s *Source) PAMRules(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PAMRule, error) {
	return passRecords[fact.PAMRule](ctx, s, fact.PAMRuleFact, agentID, runID, since)
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

// latestFacts returns, per agent ID, up to n facts of type name, newest
// first, for every agent however many there are.
func latestFacts[T any](ctx context.Context, s *Source, name string, since time.Time, n int) (map[string][]T, error) {

	sub := map[string]any{"latest": map[string]any{
		"top_hits": map[string]any{"size": n, "sort": []any{map[string]any{"timestamp": "desc"}}},
	}}

	out := map[string][]T{}

	err := s.composite(ctx, factFilter(name, since), []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "agent.id"}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Latest struct {
					Hits struct {
						Hits []hit `json:"hits"`
					} `json:"hits"`
				} `json:"latest"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			for _, h := range c.Latest.Hits.Hits {
				var v T
				if err := decodeHit(h, &v); err != nil {
					return err
				}
				out[keyString(key, "a")] = append(out[keyString(key, "a")], v)
			}
			return nil
		})

	return out, err
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

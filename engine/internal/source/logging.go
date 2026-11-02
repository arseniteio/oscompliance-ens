package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type MonitoringRecord struct {
	Time   time.Time
	Status string
}

func (s *Source) MonitoringHistory(ctx context.Context, agentID string, since time.Time) ([]MonitoringRecord, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"id": agentID}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{map[string]any{"t": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "fixed_interval": "5m"}}}, terms("s", "status")}

	var out []MonitoringRecord
	err := s.compositeIn(ctx, s.monitoring, filter, sources, nil, func(key map[string]any, _ json.RawMessage) error {
		if ms, ok := key["t"].(float64); ok {
			out = append(out, MonitoringRecord{Time: time.UnixMilli(int64(ms)).UTC(), Status: keyString(key, "s")})
		}
		return nil
	})
	return out, err
}

func (s *Source) AuditFields(ctx context.Context, agentID string, since time.Time) (int, map[string]int, error) {

	fields := map[string][]string{
		"usuario": {"data.audit.auid", "data.audit.uid"}, "objeto": {"data.audit.file.name", "data.audit.exe"},
		"tipo": {"data.audit.type"}, "resultado": {"data.audit.success"},
	}
	aggs := map[string]any{}
	for name, alts := range fields {
		should := []any{}
		for _, f := range alts {
			should = append(should, map[string]any{"exists": map[string]any{"field": f}})
		}
		aggs[name] = map[string]any{"filter": map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}}}
	}
	query := map[string]any{
		"size": 0, "track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"agent.id": agentID}},
			map[string]any{"term": map[string]any{"rule.groups": "audit"}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": aggs,
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations map[string]struct {
			Count int `json:"doc_count"`
		} `json:"aggregations"`
	}
	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return 0, nil, err
	}
	counts := map[string]int{}
	for name, a := range resp.Aggregations {
		counts[name] = a.Count
	}
	return resp.Hits.Total.Value, counts, nil
}

func (s *Source) Retention(ctx context.Context) (days int, found bool, err error) {

	var explain map[string]json.RawMessage
	if err := s.client.Do(ctx, http.MethodGet, "/_plugins/_ism/explain/"+url.PathEscape(s.index), nil, &explain); err != nil {
		return 0, false, err
	}
	policies := map[string]bool{}
	for name, raw := range explain {
		if name == "total_managed_indices" {
			continue
		}
		var e struct {
			Policy string `json:"index.plugins.index_state_management.policy_id"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Policy != "" {
			policies[e.Policy] = true
		}
	}

	shortest := 0
	for id := range policies {
		var p struct {
			Policy struct {
				States []struct {
					Name        string           `json:"name"`
					Actions     []map[string]any `json:"actions"`
					Transitions []struct {
						State      string `json:"state_name"`
						Conditions struct {
							MinIndexAge string `json:"min_index_age"`
						} `json:"conditions"`
					} `json:"transitions"`
				} `json:"states"`
			} `json:"policy"`
		}
		if err := s.client.Do(ctx, http.MethodGet, "/_plugins/_ism/policies/"+url.PathEscape(id), nil, &p); err != nil {
			return 0, false, err
		}
		deletes := map[string]bool{}
		for _, st := range p.Policy.States {
			for _, a := range st.Actions {
				if _, ok := a["delete"]; ok {
					deletes[st.Name] = true
				}
			}
		}
		for _, st := range p.Policy.States {
			for _, t := range st.Transitions {
				if !deletes[t.State] {
					continue
				}
				if d, ok := ageDays(t.Conditions.MinIndexAge); ok && (shortest == 0 || d < shortest) {
					shortest = d
				}
			}
		}
	}
	return shortest, shortest > 0, nil
}

func ageDays(v string) (int, bool) {
	if len(v) < 2 {
		return 0, false
	}
	n, err := strconv.Atoi(v[:len(v)-1])
	if err != nil {
		return 0, false
	}
	switch v[len(v)-1] {
	case 'd':
		return n, true
	case 'h':
		return n / 24, true
	case 'w':
		return n * 7, true
	}
	return 0, false
}

func (s *Source) NewestSnapshot(ctx context.Context) (time.Time, error) {

	var repos map[string]json.RawMessage
	if err := s.client.Do(ctx, http.MethodGet, "/_snapshot/_all", nil, &repos); err != nil {
		return time.Time{}, err
	}
	var newest time.Time
	for repo := range repos {
		var r struct {
			Snapshots []struct {
				State string `json:"state"`
				End   int64  `json:"end_time_in_millis"`
			} `json:"snapshots"`
		}
		if err := s.client.Do(ctx, http.MethodGet, "/_snapshot/"+url.PathEscape(repo)+"/_all", nil, &r); err != nil {
			return time.Time{}, fmt.Errorf("snapshots of %s: %w", repo, err)
		}
		for _, sn := range r.Snapshots {
			if t := time.UnixMilli(sn.End).UTC(); strings.EqualFold(sn.State, "SUCCESS") && t.After(newest) {
				newest = t
			}
		}
	}
	return newest, nil
}

package source

import (
	"context"
	"encoding/json"
	"time"
)

type AlertHour struct {
	Hour  time.Time
	Level int
}

func (s *Source) AlertHours(ctx context.Context, minLevel int, excluded []string, since time.Time) (map[string][]AlertHour, error) {

	not := []any{map[string]any{"term": map[string]any{"rule.groups": "oscompliance"}}}
	if len(excluded) > 0 {
		ids := make([]any, len(excluded))
		for i, r := range excluded {
			ids[i] = r
		}
		not = append(not, map[string]any{"terms": map[string]any{"rule.id": ids}})
	}
	filter := []any{
		map[string]any{"range": map[string]any{"rule.level": map[string]any{"gte": minLevel}}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{"must_not": not}},
	}
	sources := []any{terms("a", "agent.id"), map[string]any{"h": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "fixed_interval": "1h"}}}}
	sub := map[string]any{"top": map[string]any{"max": map[string]any{"field": "rule.level"}}}

	out := map[string][]AlertHour{}

	err := s.composite(ctx, filter, sources, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Top struct {
				Value float64 `json:"value"`
			} `json:"top"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		ms, ok := key["h"].(float64)
		if id == "" || !ok {
			return nil
		}
		out[id] = append(out[id], AlertHour{Hour: time.UnixMilli(int64(ms)).UTC(), Level: int(c.Top.Value)})
		return nil
	})

	return out, err
}

func (s *Source) ActiveResponseTimes(ctx context.Context, since time.Time) (map[string][]time.Time, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"rule.groups": "active_response"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), map[string]any{"h": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "fixed_interval": "1h"}}}}

	out := map[string][]time.Time{}
	err := s.composite(ctx, filter, sources, nil, func(key map[string]any, _ json.RawMessage) error {
		id := keyString(key, "a")
		if ms, ok := key["h"].(float64); ok && id != "" {
			out[id] = append(out[id], time.UnixMilli(int64(ms)).UTC())
		}
		return nil
	})
	return out, err
}

func (s *Source) AlertsBetween(ctx context.Context, agentID string, from, to time.Time) (int, error) {

	query := map[string]any{
		"size": 0, "track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"agent.id": agentID}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": from.UTC().Format(time.RFC3339), "lt": to.UTC().Format(time.RFC3339)}}},
		}}},
	}
	var resp struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return 0, err
	}
	return resp.Hits.Total.Value, nil
}

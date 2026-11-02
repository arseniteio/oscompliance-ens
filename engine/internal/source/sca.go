package source

import (
	"context"
	"encoding/json"
	"strconv"
	"time"
)

type SCASummary struct {
	PolicyID string
	Policy   string
	Score    int
	Passed   int
	Failed   int
	Time     time.Time
}

func (s *Source) SCASummaries(ctx context.Context, since time.Time) (map[string][]SCASummary, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"data.sca.type": "summary"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), terms("p", "data.sca.policy_id")}
	sub := map[string]any{"last": map[string]any{"top_hits": map[string]any{
		"size": 1, "sort": []any{map[string]any{"timestamp": "desc"}}, "_source": []string{"timestamp", "data.sca"},
	}}}

	out := map[string][]SCASummary{}

	err := s.composite(ctx, filter, sources, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Last struct {
				Hits struct {
					Hits []struct {
						Source struct {
							Timestamp string `json:"timestamp"`
							Data      struct {
								SCA struct {
									PolicyID string `json:"policy_id"`
									Policy   string `json:"policy"`
									Score    any    `json:"score"`
									Passed   any    `json:"passed"`
									Failed   any    `json:"failed"`
								} `json:"sca"`
							} `json:"data"`
						} `json:"_source"`
					} `json:"hits"`
				} `json:"hits"`
			} `json:"last"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		if id == "" || len(c.Last.Hits.Hits) == 0 {
			return nil
		}
		h := c.Last.Hits.Hits[0].Source
		t, err := alertTime(h.Timestamp)
		if err != nil {
			return err
		}
		sca := h.Data.SCA
		out[id] = append(out[id], SCASummary{PolicyID: sca.PolicyID, Policy: sca.Policy, Score: whole(sca.Score), Passed: whole(sca.Passed), Failed: whole(sca.Failed), Time: t})
		return nil
	})

	return out, err
}

func whole(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func (s *Source) SCALowest(ctx context.Context, since time.Time) (map[string]map[string]int, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"data.sca.type": "summary"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), terms("p", "data.sca.policy_id")}
	sub := map[string]any{"low": map[string]any{"min": map[string]any{"field": "data.sca.score"}}}

	out := map[string]map[string]int{}

	err := s.composite(ctx, filter, sources, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Low struct {
				Value *float64 `json:"value"`
			} `json:"low"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id, policy := keyString(key, "a"), keyString(key, "p")
		if id == "" || policy == "" || c.Low.Value == nil {
			return nil
		}
		if out[id] == nil {
			out[id] = map[string]int{}
		}
		out[id][policy] = int(*c.Low.Value)
		return nil
	})

	return out, err
}

type SCARegression struct {
	PolicyID string
	CheckID  string
	Title    string
	Time     time.Time
}

func (s *Source) SCARegressions(ctx context.Context, since time.Time) (map[string][]SCARegression, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"rule.id": "19007"}},
		map[string]any{"term": map[string]any{"data.sca.check.previous_result": "passed"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), terms("p", "data.sca.policy_id"), terms("c", "data.sca.check.id"), terms("t", "data.sca.check.title")}

	sub := map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}}

	out := map[string][]SCARegression{}

	err := s.composite(ctx, filter, sources, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Last struct {
				Value float64 `json:"value"`
			} `json:"last"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		if id := keyString(key, "a"); id != "" {
			out[id] = append(out[id], SCARegression{PolicyID: keyString(key, "p"), CheckID: keyString(key, "c"), Title: keyString(key, "t"), Time: time.UnixMilli(int64(c.Last.Value)).UTC()})
		}
		return nil
	})

	return out, err
}

package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Facts that Wazuh produces by itself, from its own decoders and rules. The
// agent does nothing for them; the engine reads the alerts as they are.

// authGroups are the rule groups that prove an agent's authentication log
// reaches Wazuh: v1 probed its log for the same three kinds of line.
var authGroups = []any{"authentication_success", "authentication_failed", "sudo"}

// Login is one successful sshd authentication (Wazuh rule 5715 and its
// children: groups sshd and authentication_success).
type Login struct {
	Time     time.Time
	Account  string // data.dstuser
	SourceIP string // data.srcip
	AlertID  string // the alert's id, for traceability
}

// SSHLogins returns the successful sshd logins of one agent since the given
// time, oldest first.
func (s *Source) SSHLogins(ctx context.Context, agentID string, since time.Time) ([]Login, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"rule.groups": "authentication_success"}},
		map[string]any{"term": map[string]any{"decoder.parent": "sshd"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	var logins []Login

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			Data      struct {
				DstUser string `json:"dstuser"`
				SrcIP   string `json:"srcip"`
			} `json:"data"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		// Wazuh writes "2026-10-22T11:40:01.123+0000": no colon in the offset.
		ts, err := time.Parse("2006-01-02T15:04:05.000-0700", a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: timestamp: %w", h.ID, err)
		}

		logins = append(logins, Login{Time: ts, Account: a.Data.DstUser, SourceIP: a.Data.SrcIP, AlertID: a.ID})
		return nil
	})

	return logins, err
}

// AuthActivity returns, per agent ID, the time of the newest authentication
// event (success, failure or sudo) since the given time. An agent missing from
// the map sent none: its authentication log is not reaching Wazuh, or nobody
// ever authenticated on it, and silence cannot be read as compliance.
func (s *Source) AuthActivity(ctx context.Context, since time.Time) (map[string]time.Time, error) {

	query := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.groups": authGroups}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": map[string]any{"agents": map[string]any{
			"terms": map[string]any{"field": "agent.id", "size": maxAgents},
			"aggs":  map[string]any{"newest": map[string]any{"max": map[string]any{"field": "timestamp"}}},
		}},
	}

	var resp struct {
		Aggregations struct {
			Agents struct {
				Buckets []struct {
					Key    string `json:"key"`
					Newest struct {
						Value float64 `json:"value"` // epoch milliseconds
					} `json:"newest"`
				} `json:"buckets"`
			} `json:"agents"`
		} `json:"aggregations"`
	}

	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return nil, err
	}

	activity := map[string]time.Time{}

	for _, b := range resp.Aggregations.Agents.Buckets {
		activity[b.Key] = time.UnixMilli(int64(b.Newest.Value)).UTC()
	}

	return activity, nil
}

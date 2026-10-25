package source

import (
	"context"
	"encoding/json"
	"time"
)

// ActionCount is how many times one account ran one binary or touched one
// path on one agent: audited accesses (rule 119004) and sudo runs.
type ActionCount struct {
	AgentID string
	// AUID and UID come from auditd (numbers); User from sudo (a name).
	AUID, UID, User string
	Exe             string // the binary, or the sudo command line
	Path            string // the file touched, auditd only
	Key             string // the audit key; "sudo" for sudo runs
	Count           int
	Last            time.Time
}

// AuditActions counts the audited accesses of every agent since the given
// time by agent, account, binary, path and key.
func (s *Source) AuditActions(ctx context.Context, since time.Time) ([]ActionCount, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"rule.id": AuditRule}},
		map[string]any{"term": map[string]any{"data.audit.success": "yes"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	sources := []any{
		terms("a", "agent.id"), terms("au", "data.audit.auid"), terms("u", "data.audit.uid"),
		terms("e", "data.audit.exe"), terms("p", "data.audit.file.name"), terms("k", "data.audit.key"),
	}

	var out []ActionCount

	err := s.composite(ctx, filter, sources, lastSeen, func(key map[string]any, b json.RawMessage) error {
		n, last, err := countAndLast(b)
		if err != nil {
			return err
		}
		out = append(out, ActionCount{
			AgentID: keyString(key, "a"), AUID: keyString(key, "au"), UID: keyString(key, "u"),
			Exe: keyString(key, "e"), Path: keyString(key, "p"), Key: keyString(key, "k"), Count: n, Last: last,
		})
		return nil
	})

	return out, err
}

// SudoActions counts the commands run through sudo on every agent since the
// given time by agent, user and command line.
func (s *Source) SudoActions(ctx context.Context, since time.Time) ([]ActionCount, error) {

	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": sudoSuccess}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	sources := []any{terms("a", "agent.id"), terms("u", "data.srcuser"), terms("c", "data.command")}

	var out []ActionCount

	err := s.composite(ctx, filter, sources, lastSeen, func(key map[string]any, b json.RawMessage) error {
		n, last, err := countAndLast(b)
		if err != nil {
			return err
		}
		out = append(out, ActionCount{AgentID: keyString(key, "a"), User: keyString(key, "u"), Exe: keyString(key, "c"), Key: "sudo", Count: n, Last: last})
		return nil
	})

	return out, err
}

var lastSeen = map[string]any{"t": map[string]any{"max": map[string]any{"field": "timestamp"}}}

func countAndLast(b json.RawMessage) (int, time.Time, error) {

	var c struct {
		DocCount int `json:"doc_count"`
		T        struct {
			Value float64 `json:"value"`
		} `json:"t"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return 0, time.Time{}, err
	}

	return c.DocCount, time.UnixMilli(int64(c.T.Value)).UTC(), nil
}

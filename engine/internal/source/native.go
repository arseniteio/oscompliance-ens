package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// FIM, sudo and audit alerts Wazuh raises by itself, and the facts that say
// what it watches.

// WazuhAgentConfigs returns, per agent, the newest wazuh_agent_config.
func (s *Source) WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error) {
	return newest[fact.WazuhAgentConfig](ctx, s, fact.WazuhAgentConfigFact, since)
}

// ACLSnapshots returns, per agent, the newest acl_snapshot.
func (s *Source) ACLSnapshots(ctx context.Context, since time.Time) (map[string]fact.ACLSnapshot, error) {
	return newest[fact.ACLSnapshot](ctx, s, fact.ACLSnapshotFact, since)
}

// ACLRecords returns every acl_record of one read of one agent.
func (s *Source) ACLRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ACLRecord, error) {
	return passRecords[fact.ACLRecord](ctx, s, fact.ACLRecordFact, agentID, runID, since)
}

// AuditWatchSnapshots returns, per agent, the newest audit_watch_snapshot.
func (s *Source) AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error) {
	return newest[fact.AuditWatchSnapshot](ctx, s, fact.AuditWatchSnapshotFact, since)
}

// FIMChange is one file integrity alert.
type FIMChange struct {
	Time    time.Time
	Path    string
	Event   string // added, modified, deleted
	Changed []string
	AlertID string
}

// FIMChanges returns the FIM alerts of one agent since the given time.
func (s *Source) FIMChanges(ctx context.Context, agentID string, since time.Time) ([]FIMChange, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"rule.groups": "syscheck"}},
		map[string]any{"exists": map[string]any{"field": "syscheck.path"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	var out []FIMChange

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			Syscheck  struct {
				Path    string   `json:"path"`
				Event   string   `json:"event"`
				Changed []string `json:"changed_attributes"`
			} `json:"syscheck"`
		}
		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		out = append(out, FIMChange{Time: ts, Path: a.Syscheck.Path, Event: a.Syscheck.Event, Changed: a.Syscheck.Changed, AlertID: a.ID})
		return nil
	})

	return out, err
}

// sudoSuccess are the Wazuh rules of a command run through sudo: to root,
// to another user, and the first time a user does it.
var sudoSuccess = []any{"5402", "5403", "5407"}

// sudoDenied are the rules of a refused sudo.
var sudoDenied = []any{"5401", "5404", "5405", "5406"}

// Elevation is one change of identity: sudo or su.
type Elevation struct {
	Time    time.Time
	From    string // data.srcuser
	To      string // data.dstuser
	Method  string // sudo, su
	Command string
	Denied  bool
}

// Elevations returns the sudo runs and refusals of one agent since the
// given time. su comes from Logins (PAM sessions of su).
func (s *Source) Elevations(ctx context.Context, agentID string, since time.Time) ([]Elevation, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"terms": map[string]any{"rule.id": append(append([]any{}, sudoSuccess...), sudoDenied...)}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	denied := map[string]bool{}
	for _, id := range sudoDenied {
		denied[id.(string)] = true
	}

	var out []Elevation

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Rule      struct {
				ID string `json:"id"`
			} `json:"rule"`
			Data struct {
				SrcUser string `json:"srcuser"`
				DstUser string `json:"dstuser"`
				Command string `json:"command"`
			} `json:"data"`
		}
		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		to := a.Data.DstUser
		if to == "" {
			to = "root"
		}

		out = append(out, Elevation{Time: ts, From: a.Data.SrcUser, To: to, Method: "sudo", Command: a.Data.Command, Denied: denied[a.Rule.ID]})
		return nil
	})

	return out, err
}

// AuditRule is the Wazuh rule of the audited accesses (catalog/wazuh).
const AuditRule = "119004"

// AuditAccess is one audited access to a watched path.
type AuditAccess struct {
	Time    time.Time
	Key     string // oscompliance_read, _write, _exec, _attr
	Success string
	AUID    string
	UID     string
	Path    string
	Exe     string
}

// AuditAccesses returns the audited accesses of one agent since the given
// time.
func (s *Source) AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]AuditAccess, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"rule.id": AuditRule}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	var out []AuditAccess

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Data      struct {
				Audit struct {
					Key     string `json:"key"`
					Success string `json:"success"`
					AUID    string `json:"auid"`
					UID     string `json:"uid"`
					Exe     string `json:"exe"`
					File    struct {
						Name string `json:"name"`
					} `json:"file"`
				} `json:"audit"`
			} `json:"data"`
		}
		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		x := a.Data.Audit
		out = append(out, AuditAccess{Time: ts, Key: x.Key, Success: x.Success, AUID: x.AUID, UID: x.UID, Path: x.File.Name, Exe: x.Exe})
		return nil
	})

	return out, err
}

// FirewallSnapshots returns, per agent, the newest firewall_snapshot.
func (s *Source) FirewallSnapshots(ctx context.Context, since time.Time) (map[string]fact.FirewallSnapshot, error) {
	return newest[fact.FirewallSnapshot](ctx, s, fact.FirewallSnapshotFact, since)
}

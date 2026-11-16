package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

func (s *Source) WazuhAgentConfigs(ctx context.Context, since time.Time) (map[string]fact.WazuhAgentConfig, error) {
	return newest[fact.WazuhAgentConfig](ctx, s, fact.WazuhAgentConfigFact, since)
}

func (s *Source) NeighbourSnapshots(ctx context.Context, since time.Time) (map[string]fact.NeighbourSnapshot, error) {
	return newest[fact.NeighbourSnapshot](ctx, s, fact.NeighbourSnapshotFact, since)
}

func (s *Source) Virtualizations(ctx context.Context, since time.Time) (map[string]fact.Virtualization, error) {
	return newest[fact.Virtualization](ctx, s, fact.VirtualizationFact, since)
}

func (s *Source) PackageSelections(ctx context.Context, since time.Time) (map[string]fact.PackageSelection, error) {
	return newest[fact.PackageSelection](ctx, s, fact.PackageSelectionFact, since)
}

func (s *Source) UnitSnapshots(ctx context.Context, since time.Time) (map[string]fact.UnitSnapshot, error) {
	return newest[fact.UnitSnapshot](ctx, s, fact.UnitSnapshotFact, since)
}

func (s *Source) BackupSnapshots(ctx context.Context, since time.Time) (map[string]fact.BackupSnapshot, error) {
	return newest[fact.BackupSnapshot](ctx, s, fact.BackupSnapshotFact, since)
}

func (s *Source) UpdateStatuses(ctx context.Context, since time.Time) (map[string]fact.UpdateStatus, error) {
	return newest[fact.UpdateStatus](ctx, s, fact.UpdateStatusFact, since)
}

func (s *Source) TransactionSnapshots(ctx context.Context, since time.Time) (map[string]fact.TransactionSnapshot, error) {
	return newest[fact.TransactionSnapshot](ctx, s, fact.TransactionSnapshotFact, since)
}

func (s *Source) PackageTransactions(ctx context.Context, agentID, runID string, since time.Time) ([]fact.PackageTransaction, error) {
	return passRecords[fact.PackageTransaction](ctx, s, fact.PackageTransactionFact, agentID, runID, since)
}

func (s *Source) SnapshotLists(ctx context.Context, since time.Time) (map[string]fact.SnapshotList, error) {
	return newest[fact.SnapshotList](ctx, s, fact.SnapshotListFact, since)
}

func (s *Source) MalwareProtections(ctx context.Context, since time.Time) (map[string]fact.MalwareProtection, error) {
	return newest[fact.MalwareProtection](ctx, s, fact.MalwareProtectionFact, since)
}

func (s *Source) TimeSyncs(ctx context.Context, since time.Time) (map[string]fact.TimeSync, error) {
	return newest[fact.TimeSync](ctx, s, fact.TimeSyncFact, since)
}

func (s *Source) KeySnapshots(ctx context.Context, since time.Time) (map[string]fact.KeySnapshot, error) {
	return newest[fact.KeySnapshot](ctx, s, fact.KeySnapshotFact, since)
}

func (s *Source) KeyRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.KeyRecord, error) {
	return passRecords[fact.KeyRecord](ctx, s, fact.KeyRecordFact, agentID, runID, since)
}

func (s *Source) CertificateRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.CertificateRecord, error) {
	return passRecords[fact.CertificateRecord](ctx, s, fact.CertificateRecordFact, agentID, runID, since)
}

func (s *Source) ACLSnapshots(ctx context.Context, since time.Time) (map[string]fact.ACLSnapshot, error) {
	return newest[fact.ACLSnapshot](ctx, s, fact.ACLSnapshotFact, since)
}

func (s *Source) ACLRecords(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ACLRecord, error) {
	return passRecords[fact.ACLRecord](ctx, s, fact.ACLRecordFact, agentID, runID, since)
}

func (s *Source) AuditWatchSnapshots(ctx context.Context, since time.Time) (map[string]fact.AuditWatchSnapshot, error) {
	return newest[fact.AuditWatchSnapshot](ctx, s, fact.AuditWatchSnapshotFact, since)
}

type FIMChange struct {
	Time    time.Time
	Path    string
	Event   string
	Changed []string
	AlertID string
}

func (s *Source) FIMChanges(ctx context.Context, agentID string, since time.Time) ([]FIMChange, error) {
	return batched(ctx, s, "fim|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]FIMChange, error) {
		return s.fimChanges(ctx, ids, since)
	})
}

func (s *Source) fimChanges(ctx context.Context, ids []string, since time.Time) (map[string][]FIMChange, error) {

	filter := []any{
		agentFilter(ids),
		map[string]any{"term": map[string]any{"rule.groups": "syscheck"}},
		map[string]any{"exists": map[string]any{"field": "syscheck.path"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	out := map[string][]FIMChange{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			ID        string `json:"id"`
			Timestamp string `json:"timestamp"`
			Agent     struct {
				ID string `json:"id"`
			} `json:"agent"`
			Syscheck struct {
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

		out[a.Agent.ID] = append(out[a.Agent.ID], FIMChange{Time: ts, Path: a.Syscheck.Path, Event: a.Syscheck.Event, Changed: a.Syscheck.Changed, AlertID: a.ID})
		return nil
	})

	return out, err
}

var sudoSuccess = []any{"5402", "5403", "5407"}

var sudoDenied = []any{"5401", "5404", "5405", "5406"}

type Elevation struct {
	Time    time.Time
	From    string
	To      string
	Method  string
	Command string
	Denied  bool
	Count   int
}

func (s *Source) Elevations(ctx context.Context, agentID string, since time.Time) ([]Elevation, error) {
	return batched(ctx, s, "elevations|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]Elevation, error) {
		return s.elevations(ctx, ids, since)
	})
}

func (s *Source) elevations(ctx context.Context, ids []string, since time.Time) (map[string][]Elevation, error) {

	filter := []any{
		agentFilter(ids),
		map[string]any{"terms": map[string]any{"rule.id": append(append([]any{}, sudoSuccess...), sudoDenied...)}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	denied := map[string]bool{}
	for _, id := range sudoDenied {
		denied[id.(string)] = true
	}

	sources := []any{terms("a", "agent.id"), terms("f", "data.srcuser"), terms("t", "data.dstuser"), terms("c", "data.command"), terms("r", "rule.id")}

	out := map[string][]Elevation{}

	err := s.composite(ctx, filter, sources, lastSeen, func(key map[string]any, b json.RawMessage) error {

		n, last, err := countAndLast(b)
		if err != nil {
			return err
		}

		to := keyString(key, "t")
		if to == "" {
			to = "root"
		}

		out[keyString(key, "a")] = append(out[keyString(key, "a")], Elevation{Time: last, From: keyString(key, "f"), To: to, Method: "sudo", Command: keyString(key, "c"), Denied: denied[keyString(key, "r")], Count: n})
		return nil
	})

	return out, err
}

const AuditRule = "119004"

type AuditAccess struct {
	Time    time.Time
	Key     string
	Success string
	AUID    string
	UID     string
	Path    string
	Exe     string
}

func (s *Source) AuditAccesses(ctx context.Context, agentID string, since time.Time) ([]AuditAccess, error) {
	return batched(ctx, s, "audit|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]AuditAccess, error) {
		return s.auditAccesses(ctx, ids, since)
	})
}

func (s *Source) auditAccesses(ctx context.Context, ids []string, since time.Time) (map[string][]AuditAccess, error) {

	filter := []any{
		agentFilter(ids),
		map[string]any{"term": map[string]any{"rule.id": AuditRule}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	out := map[string][]AuditAccess{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Agent     struct {
				ID string `json:"id"`
			} `json:"agent"`
			Data struct {
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
		out[a.Agent.ID] = append(out[a.Agent.ID], AuditAccess{Time: ts, Key: x.Key, Success: x.Success, AUID: x.AUID, UID: x.UID, Path: x.File.Name, Exe: x.Exe})
		return nil
	})

	return out, err
}

func (s *Source) FirewallSnapshots(ctx context.Context, since time.Time) (map[string]fact.FirewallSnapshot, error) {
	return newest[fact.FirewallSnapshot](ctx, s, fact.FirewallSnapshotFact, since)
}

func (s *Source) AgentPasses(ctx context.Context, since time.Time) (map[string]fact.AgentPass, error) {
	return newest[fact.AgentPass](ctx, s, fact.AgentPassFact, since)
}

func (s *Source) DeviceSecurities(ctx context.Context, since time.Time) (map[string]fact.DeviceSecurity, error) {
	return newest[fact.DeviceSecurity](ctx, s, fact.DeviceSecurityFact, since)
}

package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

const heldRun = "held-run"

func heldBucket(alert map[string]any) map[string]any {
	return map[string]any{
		"key":    map[string]any{"a": "001"},
		"latest": map[string]any{"hits": map[string]any{"hits": []any{map[string]any{"_id": "x", "_source": alert}}}},
	}
}

func heldIndexer(t *testing.T, name, factRun string, factAt, passAt time.Time) *Source {
	t.Helper()

	alert := func(at time.Time, data map[string]any) map[string]any {
		return map[string]any{"timestamp": at.UTC().Format("2006-01-02T15:04:05.000-0700"), "agent": map[string]any{"id": "001", "name": "m"}, "data": data}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query map[string]any
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Error(err)
		}
		raw, _ := json.Marshal(query["query"])

		var buckets []any
		seenAfter := strings.Contains(mustJSON(t, query), `"after"`)
		switch {
		case seenAfter:
		case strings.Contains(string(raw), `"data.fact":"`+fact.AgentPassFact+`"`):
			buckets = append(buckets, heldBucket(alert(passAt, map[string]any{
				"fact": fact.AgentPassFact, "ts": passAt.UTC().Format(time.RFC3339), "run_id": "last-pass", "in_force": []any{name + ":" + heldRun},
			})))
		case strings.Contains(string(raw), `"data.fact":"`+name+`"`) && !factAt.Before(rangeStart(t, string(raw))):
			buckets = append(buckets, heldBucket(alert(factAt, map[string]any{
				"fact": name, "ts": factAt.UTC().Format(time.RFC3339), "run_id": factRun,
			})))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"aggregations": map[string]any{"c": map[string]any{"buckets": buckets}}})
	}))
	t.Cleanup(server.Close)

	client, err := indexer.New(server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return New(client, "alerts", "monitoring", "states")
}

var gte = regexp.MustCompile(`"gte":"([^"]+)"`)

func rangeStart(t *testing.T, query string) time.Time {
	t.Helper()
	match := gte.FindStringSubmatch(query)
	if match == nil {
		t.Fatalf("no time range in %s", query)
	}
	at, err := time.Parse(time.RFC3339, match[1])
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var agentHeldFacts = []string{
	fact.IdentitySnapshotFact, fact.GroupSnapshotFact, fact.UmaskSnapshotFact, fact.SudoersSnapshotFact,
	fact.ConfigSnapshotFact, fact.PAMSnapshotFact, fact.ListeningSnapshotFact, fact.ServiceLogSnapshotFact,
	fact.WazuhAgentConfigFact, fact.ACLSnapshotFact, fact.AuditWatchSnapshotFact, fact.FirewallSnapshotFact,
	fact.BackupSnapshotFact, fact.DeviceSecurityFact, fact.KeySnapshotFact, fact.MalwareProtectionFact,
	fact.NeighbourSnapshotFact, fact.PackageSelectionFact, fact.SnapshotListFact, fact.TimeSyncFact,
	fact.TransactionSnapshotFact, fact.UnitSnapshotFact, fact.UpdateStatusFact, fact.VirtualizationFact,
}

func TestHeldFactOlderThanTheWindowStaysInForce(t *testing.T) {

	now := time.Date(2026, 11, 4, 21, 0, 0, 0, time.UTC)
	window := now.Add(-26 * time.Hour)

	for _, name := range agentHeldFacts {
		t.Run(name, func(t *testing.T) {
			s := heldIndexer(t, name, heldRun, now.Add(-46*time.Hour), now.Add(-time.Hour))

			got, err := readLatest[fact.Envelope](context.Background(), s, name, window, 1)
			if err != nil {
				t.Fatal(err)
			}

			list := got["001"]
			if len(list) != 1 {
				t.Fatalf("got %d facts, want the one the last pass holds", len(list))
			}
			if want := now.Add(-time.Hour).Format(time.RFC3339); list[0].TS != want {
				t.Errorf("ts %s, want the pass time %s", list[0].TS, want)
			}
		})
	}
}

func TestOldFactTheLastPassDoesNotHoldIsDropped(t *testing.T) {

	now := time.Date(2026, 11, 4, 21, 0, 0, 0, time.UTC)
	s := heldIndexer(t, fact.UnitSnapshotFact, "another-run", now.Add(-46*time.Hour), now.Add(-time.Hour))

	got, err := readLatest[fact.Envelope](context.Background(), s, fact.UnitSnapshotFact, now.Add(-26*time.Hour), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["001"]) != 0 {
		t.Errorf("got %+v, want nothing", got["001"])
	}
}

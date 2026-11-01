package source

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// VulnerabilityDay counts the open vulnerabilities of one severity a machine got on one day: the state
// index keeps no history, so the age of a vulnerability is the age of its detection.
type VulnerabilityDay struct {
	Severity string
	Detected time.Time
	Count    int
	Examples []string
}

type vulnerabilityCache struct {
	mu    sync.Mutex
	at    time.Time
	value map[string][]VulnerabilityDay
}

// Vulnerabilities reads the open vulnerabilities of every machine, by severity and day of detection.
// Several controls of a pass read them: they are read once while they stay fresh.
func (s *Source) Vulnerabilities(ctx context.Context) (map[string][]VulnerabilityDay, error) {

	c := &s.vulnerabilities
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.value != nil && time.Since(c.at) < managerFresh {
		return c.value, nil
	}
	v, err := s.readVulnerabilities(ctx)
	if err != nil {
		return nil, err
	}
	c.value, c.at = v, time.Now()
	return v, nil
}

func (s *Source) readVulnerabilities(ctx context.Context) (map[string][]VulnerabilityDay, error) {

	sources := []any{
		terms("a", "agent.id"),
		terms("s", "vulnerability.severity"),
		map[string]any{"d": map[string]any{"date_histogram": map[string]any{"field": "vulnerability.detected_at", "calendar_interval": "1d"}}},
	}
	sub := map[string]any{"cve": map[string]any{"terms": map[string]any{"field": "vulnerability.id", "size": 3}}}

	out := map[string][]VulnerabilityDay{}

	err := s.compositeIn(ctx, s.states+"vulnerabilities-*", []any{}, sources, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
			CVE   struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"cve"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		ms, ok := key["d"].(float64)
		if id == "" || !ok {
			return nil
		}
		v := VulnerabilityDay{Severity: keyString(key, "s"), Detected: time.UnixMilli(int64(ms)).UTC(), Count: c.Count}
		for _, e := range c.CVE.Buckets {
			v.Examples = append(v.Examples, e.Key)
		}
		out[id] = append(out[id], v)
		return nil
	})

	return out, err
}

// Vendors are the vendors of the packages installed on every machine.
func (s *Source) Vendors(ctx context.Context) (map[string][]string, error) {

	out := map[string][]string{}
	err := s.inventoryCount(ctx, "packages", nil, terms("v", "package.vendor"), func(id string, key map[string]any, _ int) {
		if v := keyString(key, "v"); v != "" {
			out[id] = append(out[id], v)
		}
	})
	return out, err
}

// InstalledVersions are the package versions Wazuh saw installed on some machines since a time (dpkg rule
// 2902), with the first time each was.
func (s *Source) InstalledVersions(ctx context.Context, ids []string, since time.Time) (map[string]map[string]time.Time, error) {

	out := map[string]map[string]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}

	filter := []any{
		agentFilter(ids),
		map[string]any{"term": map[string]any{"rule.id": "2902"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sub := map[string]any{"first": map[string]any{"min": map[string]any{"field": "timestamp"}}}

	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("p", "data.package"), terms("v", "data.version")}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			First struct {
				Value float64 `json:"value"`
			} `json:"first"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id, p, v := keyString(key, "a"), keyString(key, "p"), keyString(key, "v")
		if id == "" || p == "" {
			return nil
		}
		if out[id] == nil {
			out[id] = map[string]time.Time{}
		}
		out[id][p+" "+v] = time.UnixMilli(int64(c.First.Value)).UTC()
		return nil
	})

	return out, err
}

// PackageVersions are the package versions installed now on some machines, from their inventory.
func (s *Source) PackageVersions(ctx context.Context, ids []string) (map[string]map[string]bool, error) {

	out := map[string]map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}

	err := s.compositeIn(ctx, s.inventoryIndex("packages"), []any{agentFilter(ids)}, []any{terms("a", "agent.id"), terms("p", "package.name"), terms("v", "package.version")}, nil,
		func(key map[string]any, _ json.RawMessage) error {
			id := keyString(key, "a")
			if id == "" {
				return nil
			}
			if out[id] == nil {
				out[id] = map[string]bool{}
			}
			out[id][keyString(key, "p")+" "+keyString(key, "v")] = true
			return nil
		})

	return out, err
}

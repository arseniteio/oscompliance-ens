package source

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Inventory is what Syscollector keeps of a machine in the state indices: one document per item, with no date.
type Inventory struct {
	System    *System
	Hardware  *Hardware
	Packages  map[string]int
	Addresses []string
	Listening int
	Processes int
}

type System struct {
	OS           string
	Version      string
	Kernel       string
	Architecture string
}

type Hardware struct {
	Cores    int
	MemoryMB int
}

// Inventories reads the inventory of every machine at once: a handful of aggregations per pass, whatever
// the size of the fleet.
func (s *Source) Inventories(ctx context.Context) (map[string]*Inventory, error) {

	out := map[string]*Inventory{}
	of := func(id string) *Inventory {
		if out[id] == nil {
			out[id] = &Inventory{Packages: map[string]int{}}
		}
		return out[id]
	}

	steps := []struct {
		name string
		do   func() error
	}{
		{"system", func() error {
			return s.firstDocs(ctx, "system", []string{"host.os.name", "host.os.version", "host.os.kernel.release", "host.architecture"}, func(id string, src json.RawMessage) error {
				var d struct {
					Host struct {
						Architecture string `json:"architecture"`
						OS           struct {
							Name    string `json:"name"`
							Version string `json:"version"`
							Kernel  struct {
								Release string `json:"release"`
							} `json:"kernel"`
						} `json:"os"`
					} `json:"host"`
				}
				if err := json.Unmarshal(src, &d); err != nil {
					return err
				}
				of(id).System = &System{OS: d.Host.OS.Name, Version: d.Host.OS.Version, Kernel: d.Host.OS.Kernel.Release, Architecture: d.Host.Architecture}
				return nil
			})
		}},
		{"hardware", func() error {
			return s.firstDocs(ctx, "hardware", []string{"host.cpu.cores", "host.memory.total"}, func(id string, src json.RawMessage) error {
				var d struct {
					Host struct {
						CPU struct {
							Cores int `json:"cores"`
						} `json:"cpu"`
						Memory struct {
							Total int64 `json:"total"`
						} `json:"memory"`
					} `json:"host"`
				}
				if err := json.Unmarshal(src, &d); err != nil {
					return err
				}
				of(id).Hardware = &Hardware{Cores: d.Host.CPU.Cores, MemoryMB: int(d.Host.Memory.Total / (1 << 20))}
				return nil
			})
		}},
		{"packages", func() error {
			return s.inventoryCount(ctx, "packages", nil, terms("t", "package.type"), func(id string, key map[string]any, n int) {
				of(id).Packages[keyString(key, "t")] += n
			})
		}},
		{"networks", func() error {
			return s.inventoryCount(ctx, "networks", nil, terms("i", "network.ip"), func(id string, key map[string]any, n int) {
				if ip := keyString(key, "i"); ip != "" {
					of(id).Addresses = append(of(id).Addresses, ip)
				}
			})
		}},
		{"ports", func() error {
			listening := []any{map[string]any{"term": map[string]any{"interface.state": "listening"}}}
			return s.inventoryCount(ctx, "ports", listening, nil, func(id string, _ map[string]any, n int) { of(id).Listening += n })
		}},
		{"processes", func() error {
			return s.inventoryCount(ctx, "processes", nil, nil, func(id string, _ map[string]any, n int) { of(id).Processes += n })
		}},
	}

	for _, step := range steps {
		if err := step.do(); err != nil {
			return nil, fmt.Errorf("inventory %s: %w", step.name, err)
		}
	}

	return out, nil
}

func (s *Source) inventoryIndex(kind string) string {
	return s.states + "inventory-" + kind + "-*"
}

// firstDocs hands one document of each machine in an inventory index: system and hardware hold one.
func (s *Source) firstDocs(ctx context.Context, kind string, fields []string, fn func(id string, src json.RawMessage) error) error {

	sub := map[string]any{"doc": map[string]any{"top_hits": map[string]any{"size": 1, "_source": fields}}}

	return s.compositeIn(ctx, s.inventoryIndex(kind), []any{}, []any{terms("a", "agent.id")}, sub, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Doc struct {
				Hits struct {
					Hits []struct {
						Source json.RawMessage `json:"_source"`
					} `json:"hits"`
				} `json:"hits"`
			} `json:"doc"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		id := keyString(key, "a")
		if id == "" || len(c.Doc.Hits.Hits) == 0 {
			return nil
		}
		return fn(id, c.Doc.Hits.Hits[0].Source)
	})
}

// inventoryCount counts the documents of each machine, split by a second key when one is given.
func (s *Source) inventoryCount(ctx context.Context, kind string, filter []any, by any, fn func(id string, key map[string]any, n int)) error {

	if filter == nil {
		filter = []any{}
	}
	sources := []any{terms("a", "agent.id")}
	if by != nil {
		sources = append(sources, by)
	}

	return s.compositeIn(ctx, s.inventoryIndex(kind), filter, sources, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		if id := keyString(key, "a"); id != "" {
			fn(id, key, c.Count)
		}
		return nil
	})
}

// Reporting is the newest monitoring record of a machine.
type Reporting struct {
	Status        string
	LastKeepAlive time.Time
	IP            string
}

func (s *Source) Reporting(ctx context.Context, since time.Time) (map[string]Reporting, error) {

	filter := []any{map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}}}
	sub := map[string]any{"last": map[string]any{"top_hits": map[string]any{
		"size": 1, "sort": []any{map[string]any{"timestamp": "desc"}}, "_source": []string{"status", "lastKeepAlive", "ip"},
	}}}

	out := map[string]Reporting{}

	err := s.compositeIn(ctx, s.monitoring, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "id"}}}}, sub,
		func(key map[string]any, b json.RawMessage) error {
			var c struct {
				Last struct {
					Hits struct {
						Hits []struct {
							Source struct {
								Status        string `json:"status"`
								LastKeepAlive string `json:"lastKeepAlive"`
								IP            string `json:"ip"`
							} `json:"_source"`
						} `json:"hits"`
					} `json:"hits"`
				} `json:"last"`
			}
			if err := json.Unmarshal(b, &c); err != nil {
				return err
			}
			if len(c.Last.Hits.Hits) == 0 {
				return nil
			}
			h := c.Last.Hits.Hits[0].Source
			r := Reporting{Status: h.Status, IP: h.IP}
			if t, err := time.Parse(time.RFC3339, h.LastKeepAlive); err == nil {
				r.LastKeepAlive = t
			}
			out[keyString(key, "a")] = r
			return nil
		})

	return out, err
}

var packageChangeRules = []any{"2902", "2903", "2932", "2933", "2934"}

// PackageChanges counts, per machine and day, the packages Wazuh saw installed, updated or removed.
func (s *Source) PackageChanges(ctx context.Context, since time.Time) (map[string]map[time.Time]int, error) {

	filter := []any{
		map[string]any{"terms": map[string]any{"rule.id": packageChangeRules}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}
	sources := []any{terms("a", "agent.id"), map[string]any{"d": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "calendar_interval": "1d"}}}}

	out := map[string]map[time.Time]int{}

	err := s.composite(ctx, filter, sources, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		ms, ok := key["d"].(float64)
		id := keyString(key, "a")
		if !ok || id == "" {
			return nil
		}
		if out[id] == nil {
			out[id] = map[time.Time]int{}
		}
		out[id][time.UnixMilli(int64(ms)).UTC()] += c.Count
		return nil
	})

	return out, err
}

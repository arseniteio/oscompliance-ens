package source

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

type Interface struct {
	Name  string
	Type  string
	State string
}

// Network is what Wazuh's inventory holds of a machine's connections: its interfaces, addresses and
// gateways, and the processes of tunnelling tools it runs.
type Network struct {
	Interfaces []Interface
	Addresses  []string
	Gateways   []string
	Tunnels    []string
}

// UseManagerNetwork sets where the manager's own network inventory is read, since Wazuh leaves it out of
// the state indices.
func (s *Source) UseManagerNetwork(read func(ctx context.Context, tools []string) (*Network, error)) {
	s.managerNetwork = read
}

// Networks reads the network inventory of every machine; tools are the process names of tunnelling tools.
func (s *Source) Networks(ctx context.Context, tools []string) (map[string]*Network, error) {

	out := map[string]*Network{}
	of := func(id string) *Network {
		if out[id] == nil {
			out[id] = &Network{}
		}
		return out[id]
	}
	names := make([]any, len(tools))
	for i, t := range tools {
		names[i] = t
	}

	steps := []struct {
		kind   string
		filter []any
		by     []any
		add    func(id string, key map[string]any)
	}{
		{"interfaces", nil, []any{terms("n", "interface.name"), terms("t", "interface.type"), terms("s", "interface.state")}, func(id string, key map[string]any) {
			of(id).Interfaces = append(of(id).Interfaces, Interface{Name: keyString(key, "n"), Type: keyString(key, "t"), State: keyString(key, "s")})
		}},
		{"networks", nil, []any{terms("v", "network.ip")}, func(id string, key map[string]any) {
			if v := keyString(key, "v"); v != "" {
				of(id).Addresses = append(of(id).Addresses, v)
			}
		}},
		{"protocols", nil, []any{terms("v", "network.gateway")}, func(id string, key map[string]any) {
			if v := keyString(key, "v"); v != "" && v != " " {
				of(id).Gateways = append(of(id).Gateways, v)
			}
		}},
		{"processes", []any{map[string]any{"terms": map[string]any{"process.name": names}}}, []any{terms("v", "process.name")}, func(id string, key map[string]any) {
			if v := keyString(key, "v"); v != "" && !slices.Contains(of(id).Tunnels, v) {
				of(id).Tunnels = append(of(id).Tunnels, v)
			}
		}},
	}

	for _, step := range steps {
		filter := step.filter
		if filter == nil {
			filter = []any{}
		}
		sources := append([]any{terms("a", "agent.id")}, step.by...)
		err := s.compositeIn(ctx, s.inventoryIndex(step.kind), filter, sources, nil, func(key map[string]any, _ json.RawMessage) error {
			if id := keyString(key, "a"); id != "" {
				step.add(id, key)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("inventory %s: %w", step.kind, err)
		}
	}

	if s.managerNetwork != nil {
		n, err := s.managerNetwork(ctx, tools)
		if err != nil {
			return nil, fmt.Errorf("manager network: %w", err)
		}
		out[ManagerID] = n
	}
	return out, nil
}

// SourceActivity are the hours with alerts from a source since a time: an agent, a hostname as Wazuh
// decodes it, or a log location.
func (s *Source) SourceActivity(ctx context.Context, name string, since time.Time) ([]time.Time, error) {

	filter := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		sourceIs(name),
	}
	var out []time.Time
	err := s.composite(ctx, filter, []any{map[string]any{"h": map[string]any{"date_histogram": map[string]any{"field": "timestamp", "fixed_interval": "1h"}}}}, nil,
		func(key map[string]any, _ json.RawMessage) error {
			if ms, ok := key["h"].(float64); ok {
				out = append(out, time.UnixMilli(int64(ms)).UTC())
			}
			return nil
		})
	return out, err
}

func sourceIs(name string) any {
	return map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
		map[string]any{"term": map[string]any{"agent.name": name}},
		map[string]any{"term": map[string]any{"predecoder.hostname": name}},
		map[string]any{"term": map[string]any{"location": name}},
	}}}
}

// Flow is a connection a perimeter device let through, as its logs decode in Wazuh.
type Flow struct {
	Source, Destination, Protocol, Port string
	Count                               int
}

// acceptedActions are the values Wazuh's firewall decoders give data.action for a connection let through.
var acceptedActions = []any{"accept", "accepted", "allow", "allowed", "pass", "permit", "permitted", "ACCEPT", "Accept"}

// AcceptedFlows are the connections the named sources let through since a time.
func (s *Source) AcceptedFlows(ctx context.Context, names []string, since time.Time) ([]Flow, error) {

	if len(names) == 0 {
		return nil, nil
	}
	var either []any
	for _, n := range names {
		either = append(either, sourceIs(n))
	}
	filter := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"terms": map[string]any{"data.action": acceptedActions}},
		map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": either}},
	}
	sources := []any{terms("s", "data.srcip"), terms("d", "data.dstip"), terms("p", "data.protocol"), terms("o", "data.dstport")}

	var out []Flow
	err := s.composite(ctx, filter, sources, nil, func(key map[string]any, b json.RawMessage) error {
		var c struct {
			Count int `json:"doc_count"`
		}
		if err := json.Unmarshal(b, &c); err != nil {
			return err
		}
		out = append(out, Flow{Source: keyString(key, "s"), Destination: keyString(key, "d"), Protocol: keyString(key, "p"), Port: keyString(key, "o"), Count: c.Count})
		return nil
	})
	return out, err
}

// RemoteLogin is an authentication event of a machine from an address.
type RemoteLogin struct {
	Address string
	Count   int
	Last    time.Time
}

var remoteAccessGroups = []any{"sshd", "authentication_success", "authentication_failed", "authentication_failures"}

// RemoteLogins are the source addresses of the authentication events of every machine since a time.
func (s *Source) RemoteLogins(ctx context.Context, since time.Time) (map[string][]RemoteLogin, error) {

	filter := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"terms": map[string]any{"rule.groups": remoteAccessGroups}},
		map[string]any{"exists": map[string]any{"field": "data.srcip"}},
	}
	sub := map[string]any{"last": map[string]any{"max": map[string]any{"field": "timestamp"}}}

	out := map[string][]RemoteLogin{}
	err := s.composite(ctx, filter, []any{terms("a", "agent.id"), terms("i", "data.srcip")}, sub, func(key map[string]any, b json.RawMessage) error {
		d, err := detectionOf(b)
		id, ip := keyString(key, "a"), keyString(key, "i")
		if err == nil && id != "" && ip != "" {
			out[id] = append(out[id], RemoteLogin{Address: ip, Count: d.Count, Last: d.Last})
		}
		return err
	})
	return out, err
}

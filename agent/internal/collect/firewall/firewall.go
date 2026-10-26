package firewall

import (
	"encoding/json"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/host"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

type Config struct {
	Nft       string
	Iptables  string
	Ip6tables string
}

var Default = Config{Nft: "/usr/sbin/nft", Iptables: "/usr/sbin/iptables", Ip6tables: "/usr/sbin/ip6tables"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.FirewallSnapshot{Envelope: e.Envelope(fact.FirewallSnapshotFact), Status: fact.SourceRead, Chains: []fact.FirewallChain{}}

	switch {
	case host.Exists(cfg.Nft):
		s.Tool = "nft"
		out, err := host.Run(cfg.Nft, "-j", "list", "chains")
		if err == nil {
			s.Chains, err = nftChains(out)
		}
		if err != nil {
			s.Status, s.Error = fact.SourceError, err.Error()
		}
	case host.Exists(cfg.Iptables):
		s.Tool = "iptables"
		for _, t := range []struct{ bin, family string }{{cfg.Iptables, "ip"}, {cfg.Ip6tables, "ip6"}} {
			if !host.Exists(t.bin) {
				continue
			}
			out, err := host.Run(t.bin, "-S")
			if err != nil {
				s.Status, s.Error = fact.SourceError, err.Error()
				break
			}
			s.Chains = append(s.Chains, iptablesChains(out, t.family)...)
		}
	default:
		s.Tool = "none"
	}

	return e.Emit(s)
}

func nftChains(out string) ([]fact.FirewallChain, error) {

	var doc struct {
		Nftables []struct {
			Chain *struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Hook   string `json:"hook"`
				Policy string `json:"policy"`
			} `json:"chain"`
		} `json:"nftables"`
	}

	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return nil, err
	}

	chains := []fact.FirewallChain{}
	for _, item := range doc.Nftables {
		c := item.Chain
		if c == nil || (c.Hook != "input" && c.Hook != "forward") || (c.Type != "" && c.Type != "filter") {
			continue
		}
		policy := c.Policy
		if policy == "" {
			policy = "accept"
		}
		chains = append(chains, fact.FirewallChain{Family: c.Family, Table: c.Table, Name: c.Name, Hook: c.Hook, Policy: policy})
	}

	return chains, nil
}

func iptablesChains(out, family string) []fact.FirewallChain {

	var chains []fact.FirewallChain

	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "-P" && (f[1] == "INPUT" || f[1] == "FORWARD") {
			chains = append(chains, fact.FirewallChain{Family: family, Table: "filter", Name: f[1], Hook: strings.ToLower(f[1]), Policy: strings.ToLower(f[2])})
		}
	}

	return chains
}

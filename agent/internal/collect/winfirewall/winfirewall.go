package winfirewall

import (
	_ "embed"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed firewall.ps1
var script string

const Tool = "windows-firewall"

type profile struct {
	Name     string `json:"name"`
	Enabled  string `json:"enabled"`
	Inbound  string `json:"inbound"`
	Outbound string `json:"outbound"`
}

type output struct {
	Running  bool      `json:"running"`
	Profiles []profile `json:"profiles"`
}

func Collect(e *emit.Emitter, run winps.Runner) error {

	s := fact.FirewallSnapshot{Envelope: e.Envelope(fact.FirewallSnapshotFact), Tool: Tool, Status: fact.SourceRead, Chains: []fact.FirewallChain{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}
	if !out.Running {
		s.Tool = "none"
		return e.Emit(s)
	}

	for _, p := range out.Profiles {
		on := strings.EqualFold(p.Enabled, "True")
		s.Chains = append(s.Chains,
			fact.FirewallChain{Family: "windows", Table: strings.ToLower(p.Name), Name: "inbound", Hook: "input", Policy: policy(on, p.Inbound, "Block")},
			fact.FirewallChain{Family: "windows", Table: strings.ToLower(p.Name), Name: "outbound", Hook: "output", Policy: policy(on, p.Outbound, "Allow")})
	}
	return e.Emit(s)
}

// NotConfigured falls back to the Windows default for that direction.
func policy(enabled bool, action, fallback string) string {
	if !enabled {
		return "accept"
	}
	if strings.EqualFold(action, "NotConfigured") || action == "" {
		action = fallback
	}
	if strings.EqualFold(action, "Block") {
		return "drop"
	}
	return "accept"
}

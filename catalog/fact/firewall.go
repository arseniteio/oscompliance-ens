package fact

const (
	FirewallSnapshotFact = "firewall_snapshot"
)

type FirewallChain struct {
	Family string `json:"family"`
	Table  string `json:"table,omitempty"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type FirewallSnapshot struct {
	Envelope
	Tool   string          `json:"tool"`
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Chains []FirewallChain `json:"chains"`
}

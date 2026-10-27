package fact

const (
	AgentPassFact = "agent_pass"
)

type AgentPass struct {
	Envelope
	InForce []string `json:"in_force"`
}

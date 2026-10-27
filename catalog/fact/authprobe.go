package fact

const (
	AuthLogProbeFact = "auth_log_probe"
	ProbeWritten     = "written"
	ProbeError       = "error"
)

type AuthLogProbe struct {
	Envelope
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

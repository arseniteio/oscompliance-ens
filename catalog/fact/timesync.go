package fact

const (
	TimeSyncFact = "time_sync"
)

// TimeSync is how the machine keeps its clock: the service, whether it is synchronised and against what.
type TimeSync struct {
	Envelope
	Tool          string   `json:"tool"`
	Status        string   `json:"status"`
	Error         string   `json:"error,omitempty"`
	Synchronised  bool     `json:"synchronised"`
	Offset        float64  `json:"offset_seconds"`
	Sources       []string `json:"sources"`
	Authenticated bool     `json:"authenticated"`
}

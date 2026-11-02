package fact

const (
	TimeSyncFact = "time_sync"
)

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

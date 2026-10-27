package fact

const (
	ListeningSocketFact   = "listening_socket"
	ListeningSnapshotFact = "listening_snapshot"
)

type ListeningSocket struct {
	Envelope
	Protocol      string `json:"protocol"`
	Address       string `json:"local_address"`
	Port          int    `json:"local_port"`
	PID           int    `json:"process_id,omitempty"`
	Process       string `json:"process_name,omitempty"`
	Exe           string `json:"process_exe,omitempty"`
	Unit          string `json:"unit,omitempty"`
	UnitEnabled   string `json:"unit_enabled,omitempty"`
	SocketUnit    string `json:"socket_unit,omitempty"`
	SocketEnabled string `json:"socket_enabled,omitempty"`
}

type ListeningSnapshot struct {
	Envelope
	Status           string   `json:"status"`
	Error            string   `json:"error,omitempty"`
	Addresses        []string `json:"addresses"`
	ProcessesMatched bool     `json:"processes_matched,omitempty"`
	Systemd          string   `json:"systemd,omitempty"`
	RecordsEmitted   int      `json:"records_emitted"`
}

package fact

const (
	ConfigFileFact         = "config_file"
	ConfigSnapshotFact     = "config_snapshot"
	PAMRuleFact            = "pam_rule"
	PAMSnapshotFact        = "pam_snapshot"
	AuthLogProbeFact       = "auth_log_probe"
	ListeningSocketFact    = "listening_socket"
	ListeningSnapshotFact  = "listening_snapshot"
	ServiceLogFact         = "service_log"
	ServiceLogSnapshotFact = "service_log_snapshot"
)

type LogFile struct {
	Path     string `json:"path"`
	Inode    uint64 `json:"inode"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type ServiceLog struct {
	Envelope
	Service       string    `json:"service"`
	Path          string    `json:"path"`
	Status        string    `json:"status"`
	Error         string    `json:"error,omitempty"`
	Inode         uint64    `json:"inode,omitempty"`
	Size          int64     `json:"size,omitempty"`
	Modified      string    `json:"modified,omitempty"`
	Rotated       []LogFile `json:"rotated"`
	EarliestEvent string    `json:"earliest_event,omitempty"`
}

type ServiceLogSnapshot struct {
	Envelope
	Config         string `json:"config"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	AgentName      string `json:"agent_name,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

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

const (
	ProbeWritten = "written"
	ProbeError   = "error"
)

type AuthLogProbe struct {
	Envelope
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

const (
	ConfigKindFile    = "file"
	ConfigKindCommand = "command"
	SourceError       = "error"
)

type ConfigEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Line    int    `json:"line,omitempty"`
	Section string `json:"section,omitempty"`
}

type ConfigFile struct {
	Envelope
	Source  string        `json:"source"`
	Kind    string        `json:"kind"`
	Status  string        `json:"status"`
	Error   string        `json:"error,omitempty"`
	Entries []ConfigEntry `json:"entries"`
}

type ConfigSnapshot struct {
	Envelope
	RecordsEmitted int `json:"records_emitted"`
}

type PAMRule struct {
	Envelope
	Service  string   `json:"service"`
	Position int      `json:"position"`
	Type     string   `json:"type"`
	Control  string   `json:"control"`
	Module   string   `json:"module"`
	Args     []string `json:"args"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Via      []string `json:"via,omitempty"`

	ModuleMissing bool `json:"module_missing,omitempty"`
}

type PAMSnapshot struct {
	Envelope
	Services       []string `json:"services"`
	Status         string   `json:"status"`
	Error          string   `json:"error,omitempty"`
	Problems       []string `json:"problems,omitempty"`
	RecordsEmitted int      `json:"records_emitted"`
}

package fact

// Fact names of configuration observations, shared by every control that
// judges how the system is configured.
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

// LogFile is one copy of a service log.
type LogFile struct {
	Path     string `json:"path"`
	Inode    uint64 `json:"inode"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// ServiceLog mirrors service_log.v1.json. Rotated is never nil.
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

// ServiceLogSnapshot mirrors service_log_snapshot.v1.json.
type ServiceLogSnapshot struct {
	Envelope
	Config         string `json:"config"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	AgentName      string `json:"agent_name,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

// ListeningSocket mirrors listening_socket.v1.json.
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

// ListeningSnapshot mirrors listening_snapshot.v1.json.
type ListeningSnapshot struct {
	Envelope
	Status           string   `json:"status"`
	Error            string   `json:"error,omitempty"`
	Addresses        []string `json:"addresses"`
	ProcessesMatched bool     `json:"processes_matched,omitempty"`
	Systemd          string   `json:"systemd,omitempty"`
	RecordsEmitted   int      `json:"records_emitted"`
}

// Values of AuthLogProbe.Status.
const (
	ProbeWritten = "written"
	ProbeError   = "error"
)

// AuthLogProbe mirrors auth_log_probe.v1.json.
type AuthLogProbe struct {
	Envelope
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Values of ConfigFile.Kind and the extra ConfigFile.Status.
const (
	ConfigKindFile    = "file"
	ConfigKindCommand = "command"
	SourceError       = "error"
)

// ConfigEntry is one key/value setting of a ConfigFile.
type ConfigEntry struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Line    int    `json:"line,omitempty"`
	Section string `json:"section,omitempty"`
}

// ConfigFile mirrors config_file.v1.json. Entries is never nil.
type ConfigFile struct {
	Envelope
	Source  string        `json:"source"`
	Kind    string        `json:"kind"`
	Status  string        `json:"status"`
	Error   string        `json:"error,omitempty"`
	Entries []ConfigEntry `json:"entries"`
}

// ConfigSnapshot mirrors config_snapshot.v1.json.
type ConfigSnapshot struct {
	Envelope
	RecordsEmitted int `json:"records_emitted"`
}

// PAMRule mirrors pam_rule.v1.json. Args is never nil.
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
}

// PAMSnapshot mirrors pam_snapshot.v1.json.
type PAMSnapshot struct {
	Envelope
	Services       []string `json:"services"`
	Status         string   `json:"status"`
	Error          string   `json:"error,omitempty"`
	Problems       []string `json:"problems,omitempty"`
	RecordsEmitted int      `json:"records_emitted"`
}

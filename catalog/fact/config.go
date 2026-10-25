package fact

// Fact names of configuration observations, shared by every control that
// judges how the system is configured.
const (
	ConfigFileFact     = "config_file"
	ConfigSnapshotFact = "config_snapshot"
	PAMRuleFact        = "pam_rule"
	PAMSnapshotFact    = "pam_snapshot"
	AuthLogProbeFact   = "auth_log_probe"
)

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

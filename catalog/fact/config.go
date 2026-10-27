package fact

const (
	ConfigFileFact     = "config_file"
	ConfigSnapshotFact = "config_snapshot"
	ConfigKindFile     = "file"
	ConfigKindCommand  = "command"
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

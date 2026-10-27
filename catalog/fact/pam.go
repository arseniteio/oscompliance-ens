package fact

const (
	PAMRuleFact     = "pam_rule"
	PAMSnapshotFact = "pam_snapshot"
)

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

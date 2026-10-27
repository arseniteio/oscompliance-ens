package fact

const (
	SudoGrantFact       = "sudo_grant"
	SudoersSnapshotFact = "sudoers_snapshot"
)

type SudoGrant struct {
	Envelope
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	NoPasswd    bool   `json:"nopasswd,omitempty"`

	NoPasswdCommands []string `json:"nopasswd_commands,omitempty"`

	Spec string `json:"spec,omitempty"`
}

type SudoersFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type SudoDefault struct {
	Binding string `json:"binding"`
	Setting string `json:"setting"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

type SudoersSnapshot struct {
	Envelope
	Files            []SudoersFile `json:"files"`
	Status           string        `json:"status"`
	BlindSpots       int           `json:"blind_spots"`
	BlindSpotReasons []string      `json:"blind_spot_reasons,omitempty"`
	Defaults         []SudoDefault `json:"defaults,omitempty"`
	RecordsEmitted   int           `json:"records_emitted"`
}

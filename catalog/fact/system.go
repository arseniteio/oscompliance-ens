package fact

const (
	PackageSelectionFact = "package_selection"
	UnitSnapshotFact     = "unit_snapshot"
	BackupSnapshotFact   = "backup_snapshot"
)

// PackageSelection is the packages installed on request, not pulled in as dependencies.
type PackageSelection struct {
	Envelope
	Manager  string   `json:"manager"`
	Status   string   `json:"status"`
	Error    string   `json:"error,omitempty"`
	Packages []string `json:"packages"`
}

type UnitSnapshot struct {
	Envelope
	Status string   `json:"status"`
	Error  string   `json:"error,omitempty"`
	Units  []string `json:"units"`
}

type BackupSource struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Newest string `json:"newest,omitempty"`
}

type BackupSnapshot struct {
	Envelope
	Status  string         `json:"status"`
	Error   string         `json:"error,omitempty"`
	Sources []BackupSource `json:"sources"`
}

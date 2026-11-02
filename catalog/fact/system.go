package fact

const (
	PackageSelectionFact = "package_selection"
	UnitSnapshotFact     = "unit_snapshot"
	BackupSnapshotFact   = "backup_snapshot"
)

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
	Failed []string `json:"failed"`
}

type BackupSource struct {
	Source        string `json:"source"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	Newest        string `json:"newest,omitempty"`
	Oldest        string `json:"oldest,omitempty"`
	Files         int    `json:"files,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	NewestBytes   int64  `json:"newest_bytes,omitempty"`
	Truncated     bool   `json:"truncated,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Owner         string `json:"owner,omitempty"`
	GroupReadable int    `json:"group_readable,omitempty"`
	OtherReadable int    `json:"other_readable,omitempty"`
	Filesystem    string `json:"filesystem,omitempty"`
	Device        string `json:"device,omitempty"`
}

type BackupKey struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
}

type BackupSnapshot struct {
	Envelope
	Status   string         `json:"status"`
	Error    string         `json:"error,omitempty"`
	Sources  []BackupSource `json:"sources"`
	KeyFiles []BackupKey    `json:"key_files,omitempty"`
}

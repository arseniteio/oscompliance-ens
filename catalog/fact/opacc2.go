package fact

// Fact names read by op.acc.2 (and by later controls that need the same
// observations).
const (
	SpecialFileFact       = "special_file"
	FileSweepSnapshotFact = "file_sweep_snapshot"
	UmaskSnapshotFact     = "umask_snapshot"
	SudoGrantFact         = "sudo_grant"
	SudoersSnapshotFact   = "sudoers_snapshot"
)

// Values of FileSweepSnapshot.Status.
const (
	SweepComplete  = "complete"
	SweepTimeout   = "timeout"
	SweepTruncated = "truncated"
	SweepError     = "error"
)

// SourceAbsent: the file does not exist (umask and sudoers sources).
const SourceAbsent = "absent"

// SpecialFile mirrors special_file.v1.json.
type SpecialFile struct {
	Envelope
	Path          string `json:"path"`
	Kind          string `json:"kind"` // file or directory
	Mode          string `json:"mode"` // 4 octal digits
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	SUID          bool   `json:"suid"`
	SGID          bool   `json:"sgid"`
	Sticky        bool   `json:"sticky"`
	WorldWritable bool   `json:"world_writable"`
	NoOwner       bool   `json:"no_owner"`
	NoGroup       bool   `json:"no_group"`
}

// FileSweepSnapshot mirrors file_sweep_snapshot.v1.json.
type FileSweepSnapshot struct {
	Envelope
	Roots          []string `json:"roots"`
	Pruned         []string `json:"pruned,omitempty"`
	Status         string   `json:"status"`
	SweepError     string   `json:"sweep_error,omitempty"`
	Unreadable     int      `json:"unreadable"`
	RecordsEmitted int      `json:"records_emitted"`
}

// UmaskSource is one source of umask_snapshot.v1.json.
type UmaskSource struct {
	Path            string   `json:"path"`
	Status          string   `json:"status"` // read, absent, unreadable
	Error           string   `json:"error,omitempty"`
	Umasks          []string `json:"umasks,omitzero"`
	Uninterpretable []string `json:"uninterpretable,omitempty"`
}

// UmaskSnapshot mirrors umask_snapshot.v1.json.
type UmaskSnapshot struct {
	Envelope
	Sources []UmaskSource `json:"sources"`
}

// SudoGrant mirrors sudo_grant.v1.json.
type SudoGrant struct {
	Envelope
	SubjectKind string `json:"subject_kind"` // user, group, uid, gid
	Subject     string `json:"subject"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	NoPasswd    bool   `json:"nopasswd,omitempty"`
}

// SudoersFile is one file of sudoers_snapshot.v1.json.
type SudoersFile struct {
	Path   string `json:"path"`
	Status string `json:"status"` // read, absent, unreadable
	Error  string `json:"error,omitempty"`
}

// SudoersSnapshot mirrors sudoers_snapshot.v1.json.
type SudoersSnapshot struct {
	Envelope
	Files            []SudoersFile `json:"files"`
	Status           string        `json:"status"`
	BlindSpots       int           `json:"blind_spots"`
	BlindSpotReasons []string      `json:"blind_spot_reasons,omitempty"`
	RecordsEmitted   int           `json:"records_emitted"`
}

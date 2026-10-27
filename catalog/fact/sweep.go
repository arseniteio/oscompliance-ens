package fact

const (
	SpecialFileFact       = "special_file"
	FileSweepSnapshotFact = "file_sweep_snapshot"
	SweepComplete         = "complete"
	SweepTimeout          = "timeout"
	SweepTruncated        = "truncated"
	SweepError            = "error"
)

type SpecialFile struct {
	Envelope
	Path          string `json:"path"`
	Kind          string `json:"kind"`
	Mode          string `json:"mode"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	SUID          bool   `json:"suid"`
	SGID          bool   `json:"sgid"`
	Sticky        bool   `json:"sticky"`
	WorldWritable bool   `json:"world_writable"`
	NoOwner       bool   `json:"no_owner"`
	NoGroup       bool   `json:"no_group"`
}

type FileSweepSnapshot struct {
	Envelope
	Roots          []string `json:"roots"`
	Pruned         []string `json:"pruned,omitempty"`
	Status         string   `json:"status"`
	SweepError     string   `json:"sweep_error,omitempty"`
	Unreadable     int      `json:"unreadable"`
	RecordsEmitted int      `json:"records_emitted"`
}

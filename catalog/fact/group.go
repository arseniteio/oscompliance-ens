package fact

const (
	GroupRecordFact   = "group_record"
	GroupSnapshotFact = "group_snapshot"
)

type GroupRecord struct {
	Envelope
	GroupName string   `json:"group_name"`
	GID       int      `json:"gid"`
	Members   []string `json:"members"`
}

type GroupSnapshot struct {
	Envelope
	GroupPath      string `json:"group_path"`
	GroupStatus    string `json:"group_status"`
	GroupError     string `json:"group_error,omitempty"`
	RecordsEmitted *int   `json:"records_emitted,omitempty"`
}

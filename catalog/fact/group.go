package fact

// Fact names of EV-06.
const (
	GroupRecordFact   = "group_record"
	GroupSnapshotFact = "group_snapshot"
)

// GroupRecord mirrors group_record.v1.json. Members is never nil, so it is
// written as [] for a group without explicit members.
type GroupRecord struct {
	Envelope
	GroupName string   `json:"group_name"`
	GID       int      `json:"gid"`
	Members   []string `json:"members"`
}

// GroupSnapshot mirrors group_snapshot.v1.json. GroupStatus uses the Source*
// values. RecordsEmitted is set only when the file was read.
type GroupSnapshot struct {
	Envelope
	GroupPath      string `json:"group_path"`
	GroupStatus    string `json:"group_status"`
	GroupError     string `json:"group_error,omitempty"`
	RecordsEmitted *int   `json:"records_emitted,omitempty"`
}

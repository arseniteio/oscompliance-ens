package fact

const (
	ACLRecordFact   = "acl_record"
	ACLSnapshotFact = "acl_snapshot"
)

type ACLRecord struct {
	Envelope
	Path   string   `json:"path"`
	Status string   `json:"status"`
	Error  string   `json:"error,omitempty"`
	Mode   string   `json:"mode,omitempty"`
	Owner  string   `json:"owner,omitempty"`
	ACL    []string `json:"acl,omitzero"`
}

type ACLSnapshot struct {
	Envelope
	Config         string `json:"config"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

package fact

// Fact names of EV-01.
const (
	AccountRecordFact            = "account_record"
	AccountInventorySnapshotFact = "account_inventory_snapshot"
)

// Values of AccountInventorySnapshot.SourceStatus.
const (
	SourceRead        = "read"
	SourceUnreadable  = "unreadable"
	SourceImplausible = "implausible"
)

// AccountRecord mirrors account_record.v1.json.
type AccountRecord struct {
	Envelope
	User         string `json:"user"`
	UID          int    `json:"uid"`
	GID          int    `json:"gid"`
	Shell        string `json:"shell"`
	LoginEnabled bool   `json:"login_enabled"`
}

// AccountInventorySnapshot mirrors account_inventory_snapshot.v1.json. The
// pointer fields and DuplicateUIDs are set only when SourceStatus is SourceRead;
// SourceError only when it is not. On a read with no duplicates DuplicateUIDs
// must be an empty non-nil slice, so that it is written as [].
type AccountInventorySnapshot struct {
	Envelope
	Source         string         `json:"source"`
	SourcePath     string         `json:"source_path"`
	SourceStatus   string         `json:"source_status"`
	SourceError    string         `json:"source_error,omitempty"`
	UIDMin         int            `json:"uid_min"`
	EntriesTotal   *int           `json:"entries_total,omitempty"`
	RecordsEmitted *int           `json:"records_emitted,omitempty"`
	DuplicateUIDs  []DuplicateUID `json:"duplicate_uids,omitzero"`
}

// DuplicateUID is a UID shared by more than one account entry.
type DuplicateUID struct {
	UID   int      `json:"uid"`
	Users []string `json:"users"`
}

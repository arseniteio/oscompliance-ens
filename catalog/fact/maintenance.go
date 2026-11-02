package fact

const (
	UpdateStatusFact        = "update_status"
	PackageTransactionFact  = "package_transaction"
	TransactionSnapshotFact = "transaction_snapshot"
	SnapshotListFact        = "snapshot_list"
)

type UpdateStatus struct {
	Envelope
	Manager      string `json:"manager"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ListsUpdated string `json:"lists_updated,omitempty"`
	Pending      int    `json:"pending"`
	Security     int    `json:"security"`
}

type PackageTransaction struct {
	Envelope
	Start     string   `json:"start"`
	End       string   `json:"end,omitempty"`
	Actor     string   `json:"actor"`
	Command   string   `json:"command,omitempty"`
	Installed []string `json:"installed,omitempty"`
	Upgraded  []string `json:"upgraded,omitempty"`
	Removed   []string `json:"removed,omitempty"`
}

type TransactionSnapshot struct {
	Envelope
	Manager        string `json:"manager"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

type Snapshot struct {
	Tool    string `json:"tool"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

type SnapshotList struct {
	Envelope
	Status    string     `json:"status"`
	Error     string     `json:"error,omitempty"`
	Snapshots []Snapshot `json:"snapshots"`
}

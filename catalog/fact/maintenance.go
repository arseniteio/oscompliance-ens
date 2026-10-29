package fact

const (
	UpdateStatusFact        = "update_status"
	PackageTransactionFact  = "package_transaction"
	TransactionSnapshotFact = "transaction_snapshot"
	SnapshotListFact        = "snapshot_list"
)

// UpdateStatus is what the package manager would install now, and how old its package lists are.
type UpdateStatus struct {
	Envelope
	Manager      string `json:"manager"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
	ListsUpdated string `json:"lists_updated,omitempty"`
	Pending      int    `json:"pending"`
	Security     int    `json:"security"`
}

// PackageTransaction is one apt transaction of /var/log/apt/history.log.
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

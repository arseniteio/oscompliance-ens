package fact

const (
	AuditWatchSnapshotFact = "audit_watch_snapshot"
	AuditdRunning          = "running"
	AuditdStopped          = "stopped"
	AuditdAbsent           = "absent"
	AuditdError            = "error"
)

type AuditWatchSnapshot struct {
	Envelope
	Auditd string   `json:"auditd"`
	Error  string   `json:"error,omitempty"`
	Wanted []string `json:"wanted"`
	Loaded []string `json:"loaded"`
	Failed []string `json:"failed,omitempty"`

	Unloaded []string `json:"unloaded,omitempty"`

	ReadWanted []string `json:"read_wanted,omitempty"`

	ExecWanted []string `json:"exec_wanted,omitempty"`
	ExecLoaded []string `json:"exec_loaded,omitempty"`
	PermRules  int      `json:"perm_rules,omitempty"`
}

const (
	FileAccessFact = "file_access"

	AccessRead  = "read"
	AccessWrite = "write"
)

type FileAccess struct {
	Envelope
	Time    string `json:"time"`
	Watch   string `json:"watch"`
	Path    string `json:"path"`
	Access  string `json:"access"`
	Account string `json:"account"`
	Domain  string `json:"domain,omitempty"`
	Process string `json:"process_name,omitempty"`
}

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
	// NoPasswdCommands are the commands run without a password.
	NoPasswdCommands []string `json:"nopasswd_commands,omitempty"`
}

// SudoersFile is one file of sudoers_snapshot.v1.json.
type SudoersFile struct {
	Path   string `json:"path"`
	Status string `json:"status"` // read, absent, unreadable
	Error  string `json:"error,omitempty"`
}

// SudoDefault is one Defaults setting of sudoers_snapshot.v1.json.
type SudoDefault struct {
	Binding string `json:"binding"`
	Setting string `json:"setting"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

// SudoersSnapshot mirrors sudoers_snapshot.v1.json.
type SudoersSnapshot struct {
	Envelope
	Files            []SudoersFile `json:"files"`
	Status           string        `json:"status"`
	BlindSpots       int           `json:"blind_spots"`
	BlindSpotReasons []string      `json:"blind_spot_reasons,omitempty"`
	Defaults         []SudoDefault `json:"defaults,omitempty"`
	RecordsEmitted   int           `json:"records_emitted"`
}

// Fact names of the manager-driven observations of op.acc.2.
const (
	WazuhAgentConfigFact   = "wazuh_agent_config"
	ACLRecordFact          = "acl_record"
	ACLSnapshotFact        = "acl_snapshot"
	AuditWatchSnapshotFact = "audit_watch_snapshot"
)

// FIMDirectory is one FIM <directories> path of WazuhAgentConfig.
type FIMDirectory struct {
	Path     string `json:"path"`
	Realtime bool   `json:"realtime,omitempty"`
	Whodata  bool   `json:"whodata,omitempty"`
	Source   string `json:"source,omitempty"`
}

// AgentLocalfile is one <localfile> of WazuhAgentConfig.
type AgentLocalfile struct {
	Location string `json:"location"`
	Format   string `json:"format"`
	Source   string `json:"source,omitempty"`
}

// WazuhAgentConfig mirrors wazuh_agent_config.v1.json.
type WazuhAgentConfig struct {
	Envelope
	Status            string           `json:"status"`
	Error             string           `json:"error,omitempty"`
	SyscheckDisabled  bool             `json:"syscheck_disabled"`
	SyscheckFrequency int              `json:"syscheck_frequency,omitempty"`
	Directories       []FIMDirectory   `json:"directories"`
	Ignored           []string         `json:"ignored,omitempty"`
	Localfiles        []AgentLocalfile `json:"localfiles"`
}

// ACLRecord mirrors acl_record.v1.json.
type ACLRecord struct {
	Envelope
	Path   string   `json:"path"`
	Status string   `json:"status"`
	Error  string   `json:"error,omitempty"`
	Mode   string   `json:"mode,omitempty"`
	Owner  string   `json:"owner,omitempty"`
	ACL    []string `json:"acl,omitzero"`
}

// ACLSnapshot mirrors acl_snapshot.v1.json.
type ACLSnapshot struct {
	Envelope
	Config         string `json:"config"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

// Values of AuditWatchSnapshot.Auditd.
const (
	AuditdRunning = "running"
	AuditdStopped = "stopped"
	AuditdAbsent  = "absent"
	AuditdError   = "error"
)

// AuditWatchSnapshot mirrors audit_watch_snapshot.v1.json.
type AuditWatchSnapshot struct {
	Envelope
	Auditd string   `json:"auditd"`
	Error  string   `json:"error,omitempty"`
	Wanted []string `json:"wanted"`
	Loaded []string `json:"loaded"`
	Failed []string `json:"failed,omitempty"`
}

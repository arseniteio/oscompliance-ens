package fact

const (
	SpecialFileFact       = "special_file"
	FileSweepSnapshotFact = "file_sweep_snapshot"
	UmaskSnapshotFact     = "umask_snapshot"
	SudoGrantFact         = "sudo_grant"
	SudoersSnapshotFact   = "sudoers_snapshot"
)

const (
	SweepComplete  = "complete"
	SweepTimeout   = "timeout"
	SweepTruncated = "truncated"
	SweepError     = "error"
)

const SourceAbsent = "absent"

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

type UmaskSource struct {
	Path            string   `json:"path"`
	Status          string   `json:"status"`
	Error           string   `json:"error,omitempty"`
	Umasks          []string `json:"umasks,omitzero"`
	Uninterpretable []string `json:"uninterpretable,omitempty"`
}

type UmaskSnapshot struct {
	Envelope
	Sources []UmaskSource `json:"sources"`
}

type SudoGrant struct {
	Envelope
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	NoPasswd    bool   `json:"nopasswd,omitempty"`

	NoPasswdCommands []string `json:"nopasswd_commands,omitempty"`

	Spec string `json:"spec,omitempty"`
}

type SudoersFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type SudoDefault struct {
	Binding string `json:"binding"`
	Setting string `json:"setting"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

type SudoersSnapshot struct {
	Envelope
	Files            []SudoersFile `json:"files"`
	Status           string        `json:"status"`
	BlindSpots       int           `json:"blind_spots"`
	BlindSpotReasons []string      `json:"blind_spot_reasons,omitempty"`
	Defaults         []SudoDefault `json:"defaults,omitempty"`
	RecordsEmitted   int           `json:"records_emitted"`
}

const (
	WazuhAgentConfigFact   = "wazuh_agent_config"
	ACLRecordFact          = "acl_record"
	ACLSnapshotFact        = "acl_snapshot"
	AuditWatchSnapshotFact = "audit_watch_snapshot"
)

type FIMDirectory struct {
	Path     string `json:"path"`
	Realtime bool   `json:"realtime,omitempty"`
	Whodata  bool   `json:"whodata,omitempty"`
	Source   string `json:"source,omitempty"`
}

type AgentLocalfile struct {
	Location string `json:"location"`
	Format   string `json:"format"`
	Source   string `json:"source,omitempty"`
}

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

const (
	AuditdRunning = "running"
	AuditdStopped = "stopped"
	AuditdAbsent  = "absent"
	AuditdError   = "error"
)

type AuditWatchSnapshot struct {
	Envelope
	Auditd string   `json:"auditd"`
	Error  string   `json:"error,omitempty"`
	Wanted []string `json:"wanted"`
	Loaded []string `json:"loaded"`
	Failed []string `json:"failed,omitempty"`

	ExecWanted []string `json:"exec_wanted,omitempty"`
	ExecLoaded []string `json:"exec_loaded,omitempty"`
	PermRules  int      `json:"perm_rules,omitempty"`
}

const FirewallSnapshotFact = "firewall_snapshot"

type FirewallChain struct {
	Family string `json:"family"`
	Table  string `json:"table,omitempty"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type FirewallSnapshot struct {
	Envelope
	Tool   string          `json:"tool"`
	Status string          `json:"status"`
	Error  string          `json:"error,omitempty"`
	Chains []FirewallChain `json:"chains"`
}

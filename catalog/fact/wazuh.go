package fact

const (
	WazuhAgentConfigFact   = "wazuh_agent_config"
	ServiceLogFact         = "service_log"
	ServiceLogSnapshotFact = "service_log_snapshot"
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

	SyscollectorDisabled bool     `json:"syscollector_disabled"`
	SyscollectorInterval int      `json:"syscollector_interval,omitempty"`
	SyscollectorScans    []string `json:"syscollector_scans"`

	SCADisabled bool `json:"sca_disabled"`
	SCAInterval int  `json:"sca_interval,omitempty"`

	SyscheckScanOnStart bool     `json:"syscheck_scan_on_start"`
	RootcheckDisabled   bool     `json:"rootcheck_disabled"`
	Integrations        []string `json:"integrations"`
	ActiveResponses     []string `json:"active_responses"`

	SealedDays []string  `json:"sealed_days"`
	Lists      []CDBList `json:"lists"`
}

// CDBList is a list of the manager's etc/lists and when it last changed.
type CDBList struct {
	Name     string `json:"name"`
	Modified string `json:"modified"`
}

type LogFile struct {
	Path     string `json:"path"`
	Inode    uint64 `json:"inode"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

type ServiceLog struct {
	Envelope
	Service       string    `json:"service"`
	Path          string    `json:"path"`
	Status        string    `json:"status"`
	Error         string    `json:"error,omitempty"`
	Inode         uint64    `json:"inode,omitempty"`
	Size          int64     `json:"size,omitempty"`
	Modified      string    `json:"modified,omitempty"`
	Rotated       []LogFile `json:"rotated"`
	EarliestEvent string    `json:"earliest_event,omitempty"`
}

type ServiceLogSnapshot struct {
	Envelope
	Config         string `json:"config"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	AgentName      string `json:"agent_name,omitempty"`
	RecordsEmitted int    `json:"records_emitted"`
}

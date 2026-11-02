package fact

const (
	DeviceSecurityFact = "device_security"
)

type DeviceSecurity struct {
	Envelope
	Status        string   `json:"status"`
	Error         string   `json:"error,omitempty"`
	ChassisType   int      `json:"chassis_type,omitempty"`
	Portable      bool     `json:"portable"`
	Graphical     bool     `json:"graphical"`
	IdleDelay     *int     `json:"lock_idle_delay_seconds,omitempty"`
	LockEnabled   *bool    `json:"lock_enabled,omitempty"`
	LockDelay     *int     `json:"lock_delay_seconds,omitempty"`
	ShellTimeout  int      `json:"shell_timeout_seconds,omitempty"`
	ShellReadonly bool     `json:"shell_timeout_readonly,omitempty"`
	LogindIdle    int      `json:"logind_idle_seconds,omitempty"`
	RootDevice    string   `json:"root_device,omitempty"`
	RootEncrypted bool     `json:"root_encrypted"`
	Resolvers     []string `json:"dns_resolvers"`
	CPUs          int      `json:"cpu_count,omitempty"`
	LoadPercent   int      `json:"load_percent"`
	MemoryPercent int      `json:"memory_used_percent"`
	SynCookies    bool     `json:"syn_cookies"`
}

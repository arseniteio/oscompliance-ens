package fact

const (
	DeviceSecurityFact = "device_security"
)

// DeviceSecurity is how the machine protects an unattended session and its disk: its chassis, the screen
// lock of the graphical session, the idle timeouts of shells and logind, and whether its root filesystem is
// encrypted.
type DeviceSecurity struct {
	Envelope
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	ChassisType   int    `json:"chassis_type,omitempty"`
	Portable      bool   `json:"portable"`
	Graphical     bool   `json:"graphical"`
	IdleDelay     *int   `json:"lock_idle_delay_seconds,omitempty"`
	LockEnabled   *bool  `json:"lock_enabled,omitempty"`
	LockDelay     *int   `json:"lock_delay_seconds,omitempty"`
	ShellTimeout  int    `json:"shell_timeout_seconds,omitempty"`
	ShellReadonly bool   `json:"shell_timeout_readonly,omitempty"`
	LogindIdle    int    `json:"logind_idle_seconds,omitempty"`
	RootDevice    string `json:"root_device,omitempty"`
	RootEncrypted bool   `json:"root_encrypted"`
}

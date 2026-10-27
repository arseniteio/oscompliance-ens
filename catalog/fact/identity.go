package fact

const (
	IdentityRecordFact   = "identity_record"
	IdentitySnapshotFact = "identity_snapshot"
	PasswordSet          = "set"
	PasswordLocked       = "locked"
	PasswordEmpty        = "empty"
	PasswordMissing      = "missing"
	PasswordOther        = "other"
	SSHDRead             = "read"
	SSHDAbsent           = "absent"
	SSHDCommand          = "command"
	SSHDError            = "error"
)

type IdentityRecord struct {
	Envelope
	AccountName    string `json:"account_name"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	Shell          string `json:"shell"`
	PasswordState  string `json:"password_state"`
	AccountExpires string `json:"account_expires,omitempty"`

	AuthorizedKeys *int `json:"authorized_keys,omitempty"`

	PasswordChanged       string `json:"password_changed,omitempty"`
	PasswordChangeForced  bool   `json:"password_change_forced,omitempty"`
	PasswordMaxDays       *int   `json:"password_max_days,omitempty"`
	PasswordInactiveDays  *int   `json:"password_inactive_days,omitempty"`
	AuthorizedKeysChanged string `json:"authorized_keys_changed,omitempty"`
	LastLogin             string `json:"last_login,omitempty"`
}

type LoginRecordFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type IdentitySnapshot struct {
	Envelope
	PasswdPath     string `json:"passwd_path"`
	PasswdStatus   string `json:"passwd_status"`
	PasswdError    string `json:"passwd_error,omitempty"`
	ShadowPath     string `json:"shadow_path"`
	ShadowStatus   string `json:"shadow_status"`
	ShadowError    string `json:"shadow_error,omitempty"`
	RecordsEmitted *int   `json:"records_emitted,omitempty"`

	SSHDStatus          string   `json:"sshd_status"`
	SSHDError           string   `json:"sshd_error,omitempty"`
	AuthorizedKeysFiles []string `json:"authorized_keys_files,omitempty"`

	LoginRecords []LoginRecordFile `json:"login_records,omitempty"`
}

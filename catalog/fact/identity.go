package fact

// Fact names of EV-02.
const (
	IdentityRecordFact   = "identity_record"
	IdentitySnapshotFact = "identity_snapshot"
)

// Values of IdentityRecord.PasswordState.
const (
	PasswordSet     = "set"
	PasswordLocked  = "locked"
	PasswordEmpty   = "empty"
	PasswordMissing = "missing"
	PasswordOther   = "other"
)

// IdentityRecord mirrors identity_record.v1.json.
type IdentityRecord struct {
	Envelope
	AccountName    string `json:"account_name"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	Shell          string `json:"shell"`
	PasswordState  string `json:"password_state"`
	AccountExpires string `json:"account_expires,omitempty"`
	// AuthorizedKeys is nil when the number of keys cannot be known.
	AuthorizedKeys *int `json:"authorized_keys,omitempty"`

	PasswordChanged       string `json:"password_changed,omitempty"`
	PasswordChangeForced  bool   `json:"password_change_forced,omitempty"`
	PasswordMaxDays       *int   `json:"password_max_days,omitempty"`
	PasswordInactiveDays  *int   `json:"password_inactive_days,omitempty"`
	AuthorizedKeysChanged string `json:"authorized_keys_changed,omitempty"`
	LastLogin             string `json:"last_login,omitempty"`
}

// LoginRecordFile is one entry of IdentitySnapshot.LoginRecords.
type LoginRecordFile struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Values of IdentitySnapshot.SSHDStatus.
const (
	SSHDRead    = "read"
	SSHDAbsent  = "absent"
	SSHDCommand = "command"
	SSHDError   = "error"
)

// IdentitySnapshot mirrors identity_snapshot.v1.json. PasswdStatus uses the
// Source* values; ShadowStatus only SourceRead and SourceUnreadable.
// RecordsEmitted is set only when both files were read.
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

package opacc1

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// EV02Config holds the agent-side parameters of EV-02 (contract section 6).
type EV02Config struct {
	PasswdPath string
	ShadowPath string
	// SSHDPath is the sshd binary asked for its effective configuration
	// (sshd -T). Missing binary: no key logins are possible.
	SSHDPath string
}

// shadowEntry is what EV-02 reports from one shadow line. Never the hash.
type shadowEntry struct {
	passwordState  string // one of the fact.Password* values
	accountExpires string // YYYY-MM-DD, or "" when the field is empty
}

// CollectEV02 emits one identity_record per passwd entry, at any UID, joined
// with its shadow entry, then one identity_snapshot. As in EV-01, a file that
// cannot be read is reported in the snapshot, not returned as an error.
func CollectEV02(e *emit.Emitter, cfg EV02Config) error {

	snapshot := fact.IdentitySnapshot{
		Envelope:   e.Envelope(fact.IdentitySnapshotFact),
		PasswdPath: cfg.PasswdPath,
		ShadowPath: cfg.ShadowPath,
	}

	entries, err := readPasswd(cfg.PasswdPath)

	if err != nil {
		snapshot.PasswdStatus = fact.SourceUnreadable
		snapshot.PasswdError = err.Error()
		return emitWithoutShadow(e, snapshot)
	}

	if !hasRoot(entries) {
		snapshot.PasswdStatus = fact.SourceImplausible
		snapshot.PasswdError = fmt.Sprintf("%s has no entry with UID 0", cfg.PasswdPath)
		return emitWithoutShadow(e, snapshot)
	}

	snapshot.PasswdStatus = fact.SourceRead

	shadow, err := readShadow(cfg.ShadowPath)

	if err != nil {
		snapshot.ShadowStatus = fact.SourceUnreadable
		snapshot.ShadowError = err.Error()
		snapshot.SSHDStatus = fact.SSHDError
		snapshot.SSHDError = "not asked: " + cfg.ShadowPath + " was not read"
		return e.Emit(snapshot)
	}

	snapshot.ShadowStatus = fact.SourceRead

	// Where sshd looks for keys. Asked once per pass, not per account.
	keys := readSSHD(cfg.SSHDPath)

	snapshot.SSHDStatus = keys.status
	snapshot.SSHDError = keys.err
	snapshot.AuthorizedKeysFiles = keys.files

	recordsEmitted := 0

	for _, entry := range entries {

		// An account with no shadow line is reported, not skipped: a missing
		// entry is itself something an auditor wants to see.
		state := shadowEntry{passwordState: fact.PasswordMissing}

		if s, ok := shadow[entry.user]; ok {
			state = s
		}

		record := fact.IdentityRecord{
			Envelope:       e.Envelope(fact.IdentityRecordFact),
			AccountName:    entry.user,
			UID:            entry.uid,
			GID:            entry.gid,
			Shell:          entry.shell,
			PasswordState:  state.passwordState,
			AccountExpires: state.accountExpires,
			AuthorizedKeys: keys.count(entry),
		}

		if err := e.Emit(record); err != nil {
			return err
		}

		recordsEmitted++
	}

	snapshot.RecordsEmitted = &recordsEmitted

	// Emitted last: it tells the engine the pass is complete.
	return e.Emit(snapshot)
}

// emitWithoutShadow emits a snapshot whose passwd was not read. Shadow is not
// attempted: without passwd there is nothing to join it to.
func emitWithoutShadow(e *emit.Emitter, snapshot fact.IdentitySnapshot) error {

	snapshot.ShadowStatus = fact.SourceUnreadable
	snapshot.ShadowError = "not read: " + snapshot.PasswdPath + " was not read"

	// No accounts, so no keys to count: sshd is not asked.
	snapshot.SSHDStatus = fact.SSHDError
	snapshot.SSHDError = "not asked: " + snapshot.PasswdPath + " was not read"

	return e.Emit(snapshot)
}

// readShadow parses the shadow file into one shadowEntry per account name.
// Same rules as readPasswd: the whole file is read before anything is
// emitted, malformed lines (not 9 fields, empty name) are skipped, and only an
// open or read error is returned. When a name appears twice, the first wins.
func readShadow(path string) (map[string]shadowEntry, error) {

	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	entries := map[string]shadowEntry{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ":")
		if len(fields) != 9 || fields[0] == "" {
			continue
		}

		if _, seen := entries[fields[0]]; seen {
			continue
		}

		entries[fields[0]] = shadowEntry{
			passwordState:  passwordState(fields[1]),
			accountExpires: accountExpires(fields[7]),
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return entries, nil
}

// passwordState classifies the shadow password field (field 2) without ever
// keeping it:
//
//	""             -> fact.PasswordEmpty
//	"!..." "*..."  -> fact.PasswordLocked
//	"$..."         -> fact.PasswordSet
//	anything else  -> fact.PasswordOther
func passwordState(field string) string {

	switch {
	case field == "":
		return fact.PasswordEmpty
	case strings.HasPrefix(field, "!"), strings.HasPrefix(field, "*"):
		return fact.PasswordLocked
	case strings.HasPrefix(field, "$"):
		return fact.PasswordSet
	default:
		return fact.PasswordOther
	}
}

// accountExpires converts shadow field 8 (days since 1970-01-01) to a
// YYYY-MM-DD date in UTC. An empty or non-numeric field returns "".
func accountExpires(field string) string {

	// parseID (ev01.go) already accepts only unsigned decimals: "-1" and
	// "abc" fail here and mean "no date".
	days, err := parseID(field)

	if err != nil {
		return ""
	}

	// Go writes date layouts with its reference date, 2006-01-02.
	return time.Unix(int64(days)*24*60*60, 0).UTC().Format("2006-01-02")
}

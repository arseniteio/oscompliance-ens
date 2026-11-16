package accounts

import (
	"bufio"
	"fmt"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type IdentityConfig struct {
	PasswdPath string
	ShadowPath string

	SSHDPath string

	LoginRecords []string
	LastlogPath  string
}

type shadowEntry struct {
	passwordState  string
	accountExpires string
	changed        string
	changeForced   bool
	maxDays        *int
	inactiveDays   *int
}

func CollectIdentity(e *emit.Emitter, cfg IdentityConfig) error {

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

	keys := readSSHD(cfg.SSHDPath)

	snapshot.SSHDStatus = keys.status
	snapshot.SSHDError = keys.err
	snapshot.AuthorizedKeysFiles = keys.files

	logins, sources := readLogins(cfg.LoginRecords, cfg.LastlogPath, entries)
	snapshot.LoginRecords = sources

	recordsEmitted := 0

	for _, entry := range entries {

		state := shadowEntry{passwordState: fact.PasswordMissing}

		if s, ok := shadow[entry.user]; ok {
			state = s
		}

		key := keys.inspect(entry)

		record := fact.IdentityRecord{
			Envelope:             e.Envelope(fact.IdentityRecordFact),
			AccountName:          entry.user,
			UID:                  entry.uid,
			GID:                  entry.gid,
			Shell:                entry.shell,
			PasswordState:        state.passwordState,
			AccountExpires:       state.accountExpires,
			AuthorizedKeys:       key.count,
			PasswordChanged:      state.changed,
			PasswordChangeForced: state.changeForced,
			PasswordMaxDays:      state.maxDays,
			PasswordInactiveDays: state.inactiveDays,
		}

		if !key.changed.IsZero() {
			record.AuthorizedKeysChanged = key.changed.UTC().Format(time.RFC3339)
		}

		if last, ok := logins[entry.user]; ok {
			record.LastLogin = last.UTC().Format(time.RFC3339)
		}

		if err := e.Emit(record); err != nil {
			return err
		}

		recordsEmitted++
	}

	snapshot.RecordsEmitted = &recordsEmitted

	return e.Emit(snapshot)
}

func emitWithoutShadow(e *emit.Emitter, snapshot fact.IdentitySnapshot) error {

	snapshot.ShadowStatus = fact.SourceUnreadable
	snapshot.ShadowError = "not read: " + snapshot.PasswdPath + " was not read"

	snapshot.SSHDStatus = fact.SSHDError
	snapshot.SSHDError = "not asked: " + snapshot.PasswdPath + " was not read"

	return e.Emit(snapshot)
}

func readShadow(path string) (map[string]shadowEntry, error) {

	file, err := fsread.Open(path)

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

		entry := shadowEntry{
			passwordState:  passwordState(fields[1]),
			accountExpires: shadowDate(fields[7]),
			changed:        shadowDate(fields[2]),
			changeForced:   fields[2] == "0",
			maxDays:        optionalDays(fields[4]),
			inactiveDays:   optionalDays(fields[6]),
		}

		if entry.changeForced {
			entry.changed = ""
		}

		entries[fields[0]] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return entries, nil
}

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

func optionalDays(field string) *int {

	days, err := parseID(field)

	if err != nil {
		return nil
	}

	return &days
}

func shadowDate(field string) string {

	days, err := parseID(field)

	if err != nil {
		return ""
	}

	return time.Unix(int64(days)*24*60*60, 0).UTC().Format("2006-01-02")
}

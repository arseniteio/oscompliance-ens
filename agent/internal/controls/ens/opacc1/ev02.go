package opacc1

import (
	"fmt"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// EV02Config holds the agent-side parameters of EV-02 (contract section 6).
type EV02Config struct {
	PasswdPath string
	ShadowPath string
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
		return e.Emit(snapshot)
	}

	snapshot.ShadowStatus = fact.SourceRead

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

	return e.Emit(snapshot)
}

// readShadow parses the shadow file into one shadowEntry per account name.
// Same rules as readPasswd: the whole file is read before anything is
// emitted, malformed lines (not 9 fields, empty name) are skipped, and only an
// open or read error is returned. When a name appears twice, the first wins.
func readShadow(path string) (map[string]shadowEntry, error) {
	// TODO(dioni): open path, scan lines, split on ":", fill the map with
	// passwordState(fields[1]) and accountExpires(fields[7]).
	return nil, fmt.Errorf("readShadow not implemented")
}

// passwordState classifies the shadow password field (field 2) without ever
// keeping it:
//
//	""             -> fact.PasswordEmpty
//	"!..." "*..."  -> fact.PasswordLocked
//	"$..."         -> fact.PasswordSet
//	anything else  -> fact.PasswordOther
func passwordState(field string) string {
	// TODO(dioni)
	return ""
}

// accountExpires converts shadow field 8 (days since 1970-01-01) to a
// YYYY-MM-DD date in UTC. An empty or non-numeric field returns "".
func accountExpires(field string) string {
	// TODO(dioni)
	return ""
}

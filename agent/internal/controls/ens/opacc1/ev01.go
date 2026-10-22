// Package opacc1 collects the facts of ENS control op.acc.1.
package opacc1

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// EV01Config holds the agent-side parameters of EV-01 (contract section 6).
type EV01Config struct {
	PasswdPath string
	UIDMin     int
}

// passwdEntry is one well-formed line of the account database.
type passwdEntry struct {
	user  string
	uid   int
	gid   int
	home  string
	shell string
}

// CollectEV01 reads the account database and emits one account_record per
// account with UID >= UIDMin, then one account_inventory_snapshot. The
// snapshot is emitted even when the source cannot be read: a source that
// cannot be read is a fact, not an agent failure. The returned error is only
// about emitting.
func CollectEV01(e *emit.Emitter, cfg EV01Config) error {

	snapshot := fact.AccountInventorySnapshot{
		Envelope:   e.Envelope(fact.AccountInventorySnapshotFact),
		Source:     "passwd",
		SourcePath: cfg.PasswdPath,
		UIDMin:     cfg.UIDMin,
	}

	entries, err := readPasswd(cfg.PasswdPath)

	if err != nil {
		snapshot.SourceStatus = fact.SourceUnreadable
		snapshot.SourceError = err.Error()
		return e.Emit(snapshot)
	}

	// An empty or truncated file would otherwise report zero accounts as a
	// clean inventory. Every real account database has a UID 0 entry.
	if !hasRoot(entries) {
		snapshot.SourceStatus = fact.SourceImplausible
		snapshot.SourceError = fmt.Sprintf("%s has no entry with UID 0", cfg.PasswdPath)
		return e.Emit(snapshot)
	}

	recordsEmitted := 0

	for _, entry := range entries {

		if entry.uid < cfg.UIDMin {
			continue
		}

		record := fact.AccountRecord{
			Envelope:     e.Envelope(fact.AccountRecordFact),
			AccountName:  entry.user,
			UID:          entry.uid,
			GID:          entry.gid,
			Shell:        entry.shell,
			LoginEnabled: loginEnabled(entry.shell),
		}

		if err := e.Emit(record); err != nil {
			return err
		}

		recordsEmitted++
	}

	entriesTotal := len(entries)

	snapshot.SourceStatus = fact.SourceRead
	snapshot.EntriesTotal = &entriesTotal
	snapshot.RecordsEmitted = &recordsEmitted
	snapshot.DuplicateUIDs = duplicateUIDs(entries)

	// Emitted last: it tells the engine the pass is complete.
	return e.Emit(snapshot)
}

// readPasswd parses the whole file before anything is emitted, so that a read
// error halfway never leaves records without their snapshot. Lines that are not
// a well-formed passwd entry are skipped, as v1 did.
func readPasswd(path string) ([]passwdEntry, error) {

	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var entries []passwdEntry

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" {
			continue
		}

		uid, err := parseID(fields[2])

		if err != nil {
			continue
		}

		gid, err := parseID(fields[3])

		if err != nil {
			continue
		}

		entries = append(entries, passwdEntry{
			user:  fields[0],
			uid:   uid,
			gid:   gid,
			home:  fields[5],
			shell: fields[6],
		})
	}

	// Covers I/O errors and paths that are not regular files, like a directory.
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return entries, nil
}

// parseID accepts only unsigned decimal IDs: Atoi would also take "-1" and "+5".
func parseID(s string) (int, error) {

	id, err := strconv.ParseUint(s, 10, 32)

	if err != nil {
		return 0, err
	}

	return int(id), nil
}

func hasRoot(entries []passwdEntry) bool {

	for _, entry := range entries {
		if entry.uid == 0 {
			return true
		}
	}

	return false
}

// loginEnabled follows the v1 definition of an active account: an empty shell
// means /bin/sh, so it can log in.
func loginEnabled(shell string) bool {
	return !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
}

// duplicateUIDs checks every entry, not only those above UIDMin. It never
// returns nil: the schema requires [] when there are no duplicates.
func duplicateUIDs(entries []passwdEntry) []fact.DuplicateUID {

	usersByUID := map[int][]string{}

	for _, entry := range entries {
		usersByUID[entry.uid] = append(usersByUID[entry.uid], entry.user)
	}

	duplicates := []fact.DuplicateUID{}

	for uid, users := range usersByUID {
		if len(users) > 1 {
			duplicates = append(duplicates, fact.DuplicateUID{UID: uid, AccountNames: users})
		}
	}

	// Map order is random; a stable order keeps the facts comparable between passes.
	sort.Slice(duplicates, func(i, j int) bool { return duplicates[i].UID < duplicates[j].UID })

	return duplicates
}

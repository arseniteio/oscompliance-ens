package opacc1

import (
	"bufio"
	"fmt"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// EV06Config holds the agent-side parameters of EV-06 (contract section 6).
// Which groups grant privilege (P-11) and the admin suffix (P-12) are engine
// parameters: the agent reports every group.
type EV06Config struct {
	GroupPath string
}

// groupEntry is one well-formed line of the group file.
type groupEntry struct {
	name    string
	gid     int
	members []string
}

// CollectEV06 emits one group_record per group, then one group_snapshot. As
// in EV-01, a file that cannot be read is reported in the snapshot, not
// returned as an error.
func CollectEV06(e *emit.Emitter, cfg EV06Config) error {

	snapshot := fact.GroupSnapshot{
		Envelope:  e.Envelope(fact.GroupSnapshotFact),
		GroupPath: cfg.GroupPath,
	}

	groups, err := readGroup(cfg.GroupPath)

	if err != nil {
		snapshot.GroupStatus = fact.SourceUnreadable
		snapshot.GroupError = err.Error()
		return e.Emit(snapshot)
	}

	// Same guard as passwd: an empty or truncated file would look like a
	// system where nobody holds privilege.
	if !hasRootGroup(groups) {
		snapshot.GroupStatus = fact.SourceImplausible
		snapshot.GroupError = fmt.Sprintf("%s has no entry with GID 0", cfg.GroupPath)
		return e.Emit(snapshot)
	}

	recordsEmitted := 0

	for _, group := range groups {

		record := fact.GroupRecord{
			Envelope:  e.Envelope(fact.GroupRecordFact),
			GroupName: group.name,
			GID:       group.gid,
			Members:   group.members,
		}

		if err := e.Emit(record); err != nil {
			return err
		}

		recordsEmitted++
	}

	snapshot.GroupStatus = fact.SourceRead
	snapshot.RecordsEmitted = &recordsEmitted

	// Emitted last: it tells the engine the pass is complete.
	return e.Emit(snapshot)
}

// readGroup parses the whole group file before anything is emitted. Lines
// that are not name:password:gid:members are skipped, as in readPasswd.
func readGroup(path string) ([]groupEntry, error) {

	file, err := fsread.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var groups []groupEntry

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ":")
		if len(fields) != 4 || fields[0] == "" {
			continue
		}

		gid, err := parseID(fields[2])

		if err != nil {
			continue
		}

		// Never nil, so an empty group is written as [] (schema).
		members := []string{}

		for _, member := range strings.Split(fields[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}

		groups = append(groups, groupEntry{name: fields[0], gid: gid, members: members})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return groups, nil
}

func hasRootGroup(groups []groupEntry) bool {

	for _, group := range groups {
		if group.gid == 0 {
			return true
		}
	}

	return false
}

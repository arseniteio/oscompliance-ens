package accounts

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type GroupsConfig struct {
	GroupPath string
}

type groupEntry struct {
	name    string
	gid     int
	members []string
}

func CollectGroups(e *emit.Emitter, cfg GroupsConfig) error {

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

	return e.Emit(snapshot)
}

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

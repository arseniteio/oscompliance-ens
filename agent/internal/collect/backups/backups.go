// Package backups dates the newest copy of each configuration source the manager declares: the last
// commit of a git directory (as etckeeper keeps /etc) or the newest file a pattern matches.
package backups

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

const gitPrefix = "git:"

type Config struct {
	Wazuh wazuh.AgentConfigPaths
}

// Collect reads the sources from the group configuration the engine writes (`backup_sources`).
func Collect(e *emit.Emitter, cfg Config) error {
	paths, ok, err := wazuh.ReadSharedPaths(cfg.Wazuh)
	if err != nil {
		s := fact.BackupSnapshot{Envelope: e.Envelope(fact.BackupSnapshotFact), Status: fact.SourceUnreadable, Error: err.Error(), Sources: []fact.BackupSource{}}
		return e.Emit(s)
	}
	return collect(e, paths.BackupSources, ok)
}

func collect(e *emit.Emitter, sources []string, configured bool) error {

	s := fact.BackupSnapshot{Envelope: e.Envelope(fact.BackupSnapshotFact), Status: fact.SourceRead, Sources: []fact.BackupSource{}}
	if !configured {
		s.Status = fact.SourceAbsent
		return e.Emit(s)
	}

	for _, src := range sources {
		b := fact.BackupSource{Source: src, Status: fact.SourceRead}
		var newest time.Time
		var err error
		if dir, ok := strings.CutPrefix(src, gitPrefix); ok {
			newest, err = lastCommit(dir)
		} else {
			newest, err = newestFile(src)
		}
		switch {
		case errors.Is(err, fs.ErrNotExist):
			b.Status = fact.SourceAbsent
		case err != nil:
			b.Status, b.Error = fact.SourceError, err.Error()
		default:
			b.Newest = newest.UTC().Format(time.RFC3339)
		}
		s.Sources = append(s.Sources, b)
	}

	return e.Emit(s)
}

// lastCommit reads the time of the last entry of the HEAD reflog, without running git.
func lastCommit(dir string) (time.Time, error) {

	data, err := fsread.ReadFile(filepath.Join(dir, ".git", "logs", "HEAD"))
	if err != nil {
		return time.Time{}, err
	}

	var last string
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	for lines.Scan() {
		if l := strings.TrimSpace(lines.Text()); l != "" {
			last = l
		}
	}

	// <old> <new> <name> <email> <epoch> <zone>\t<message>
	head, _, _ := strings.Cut(last, "\t")
	f := strings.Fields(head)
	if len(f) < 2 {
		return time.Time{}, fs.ErrNotExist
	}
	epoch, err := strconv.ParseInt(f[len(f)-2], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("reflog of %s: %w", dir, err)
	}
	return time.Unix(epoch, 0), nil
}

func newestFile(pattern string) (time.Time, error) {

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return time.Time{}, err
	}

	var newest time.Time
	for _, m := range matches {
		info, err := os.Stat(m)
		if err == nil && info.Mode().IsRegular() && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	if newest.IsZero() {
		return time.Time{}, fs.ErrNotExist
	}
	return newest, nil
}

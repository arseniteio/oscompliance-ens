package backups

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

const (
	gitPrefix = "git:"
	Mountinfo = "/proc/self/mountinfo"
	maxFiles  = 100000
)

type Config struct {
	Wazuh  wazuh.AgentConfigPaths
	Mounts string
}

func Collect(e *emit.Emitter, cfg Config) error {
	paths, ok, err := wazuh.ReadSharedPaths(cfg.Wazuh)
	if err != nil {
		s := fact.BackupSnapshot{Envelope: e.Envelope(fact.BackupSnapshotFact), Status: fact.SourceUnreadable, Error: err.Error(), Sources: []fact.BackupSource{}}
		return e.Emit(s)
	}
	return collect(e, paths.BackupSources, paths.BackupKeys, ok, readMounts(cfg.Mounts))
}

func collect(e *emit.Emitter, sources, keys []string, configured bool, mounts []mount) error {

	s := fact.BackupSnapshot{Envelope: e.Envelope(fact.BackupSnapshotFact), Status: fact.SourceRead, Sources: []fact.BackupSource{}}
	if !configured {
		s.Status = fact.SourceAbsent
		return e.Emit(s)
	}

	for _, src := range sources {
		s.Sources = append(s.Sources, source(src, mounts))
	}
	for _, k := range keys {
		s.KeyFiles = append(s.KeyFiles, key(k))
	}

	return e.Emit(s)
}

func source(src string, mounts []mount) fact.BackupSource {

	b := fact.BackupSource{Source: src, Status: fact.SourceRead}

	var c copies
	var err error
	var root string
	if dir, ok := strings.CutPrefix(src, gitPrefix); ok {
		root = dir
		c, err = commits(dir)
	} else {
		root = fixedPart(src)
		c, err = files(src)
	}

	switch {
	case errors.Is(err, fs.ErrNotExist):
		b.Status = fact.SourceAbsent
		return b
	case err != nil:
		b.Status, b.Error = fact.SourceError, err.Error()
		return b
	}

	b.Newest, b.Oldest = stamp(c.newest), stamp(c.oldest)
	b.Files, b.Bytes, b.NewestBytes, b.Truncated = c.count, c.bytes, c.newestBytes, c.truncated
	b.GroupReadable, b.OtherReadable = c.groupReadable, c.otherReadable
	if info, err := os.Stat(root); err == nil {
		b.Mode, b.Owner = fmt.Sprintf("%04o", info.Mode().Perm()), ownerOf(info)
	}
	if m, ok := mountOf(root, mounts); ok {
		b.Filesystem, b.Device = m.fstype, m.device
	}
	return b
}

func key(path string) fact.BackupKey {
	k := fact.BackupKey{Path: path, Status: fact.SourceRead}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		k.Status = fact.SourceAbsent
	case err != nil:
		k.Status, k.Error = fact.SourceError, err.Error()
	default:
		k.Mode, k.Owner = fmt.Sprintf("%04o", info.Mode().Perm()), ownerOf(info)
	}
	return k
}

type copies struct {
	newest, oldest               time.Time
	count                        int
	bytes, newestBytes           int64
	truncated                    bool
	groupReadable, otherReadable int
}

func (c *copies) add(info fs.FileInfo) {

	t := info.ModTime()
	if c.newest.IsZero() || t.After(c.newest) {
		c.newest, c.newestBytes = t, info.Size()
	}
	if c.oldest.IsZero() || t.Before(c.oldest) {
		c.oldest = t
	}
	c.count++
	c.bytes += info.Size()
	if info.Mode().Perm()&0o040 != 0 {
		c.groupReadable++
	}
	if info.Mode().Perm()&0o004 != 0 {
		c.otherReadable++
	}
}

func commits(dir string) (copies, error) {

	data, err := fsread.ReadFile(filepath.Join(dir, ".git", "logs", "HEAD"))
	if err != nil {
		return copies{}, err
	}

	var c copies
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	for lines.Scan() {
		head, _, _ := strings.Cut(strings.TrimSpace(lines.Text()), "\t")
		f := strings.Fields(head)
		if len(f) < 2 {
			continue
		}
		epoch, err := strconv.ParseInt(f[len(f)-2], 10, 64)
		if err != nil {
			return copies{}, fmt.Errorf("reflog of %s: %w", dir, err)
		}
		t := time.Unix(epoch, 0)
		if c.oldest.IsZero() {
			c.oldest = t
		}
		c.newest = t
		c.count++
	}
	if c.count == 0 {
		return copies{}, fs.ErrNotExist
	}
	return c, nil
}

func files(pattern string) (copies, error) {

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return copies{}, err
	}

	var c copies
	for _, m := range matches {
		err := filepath.WalkDir(m, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			if c.count >= maxFiles {
				c.truncated = true
				return filepath.SkipAll
			}
			if info, err := d.Info(); err == nil {
				c.add(info)
			}
			return nil
		})
		if err != nil {
			return copies{}, err
		}
	}
	if c.count == 0 {
		return copies{}, fs.ErrNotExist
	}
	return c, nil
}

func fixedPart(pattern string) string {
	parts := strings.Split(filepath.Clean(pattern), string(filepath.Separator))
	for i, p := range parts {
		if strings.ContainsAny(p, "*?[") {
			return string(filepath.Separator) + filepath.Join(parts[:i]...)
		}
	}
	return filepath.Clean(pattern)
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func ownerOf(info fs.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	name := strconv.FormatUint(uint64(st.Uid), 10)
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	group := strconv.FormatUint(uint64(st.Gid), 10)
	if g, err := user.LookupGroupId(group); err == nil {
		group = g.Name
	}
	return name + ":" + group
}

type mount struct {
	point, fstype, device string
}

func readMounts(path string) []mount {

	data, err := fsread.ReadFile(path)
	if err != nil {
		return nil
	}

	var out []mount
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	for lines.Scan() {
		before, after, found := strings.Cut(lines.Text(), " - ")
		f, tail := strings.Fields(before), strings.Fields(after)
		if !found || len(f) < 5 || len(tail) < 2 {
			continue
		}
		out = append(out, mount{point: unescape(f[4]), fstype: tail[0], device: unescape(tail[1])})
	}
	return out
}

func mountOf(path string, mounts []mount) (mount, bool) {
	var best mount
	found := false
	for _, m := range mounts {
		if (path == m.point || m.point == "/" || strings.HasPrefix(path, m.point+"/")) && len(m.point) >= len(best.point) {
			best, found = m, true
		}
	}
	return best, found
}

func unescape(s string) string {
	if v, err := strconv.Unquote(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`); err == nil {
		return v
	}
	return s
}

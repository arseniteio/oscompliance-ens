// Package opacc2 collects the facts of ENS control op.acc.2 that no Wazuh
// module provides: a sweep of special files, the declared umask and the
// sudoers grants. Which values comply is the engine's decision.
package sweep

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// Config holds the agent-side parameters of the filesystem sweep.
type Config struct {
	// MountsPath lists the mounted filesystems (/proc/self/mounts).
	MountsPath string
	// Roots, when set, replaces the local filesystems found in MountsPath.
	Roots []string
	// Prune are directories never entered.
	Prune []string
	// PasswdPath and GroupPath tell which uid and gid exist.
	PasswdPath string
	GroupPath  string
	// Timeout bounds the whole sweep; MaxRecords bounds what is emitted.
	Timeout    time.Duration
	MaxRecords int
}

// DefaultPrune are pseudo, runtime and container filesystems: nothing there
// is an installed file of the host.
var DefaultPrune = []string{"/proc", "/sys", "/run", "/dev", "/snap", "/var/lib/docker", "/var/lib/containers"}

// localTypes are the filesystem types swept when Roots is not given.
var localTypes = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "jfs": true, "f2fs": true, "reiserfs": true}

// Collect walks every local filesystem and emits one special_file per
// file or directory with SUID, SGID, world-write or no owner or group, then
// the file_sweep_snapshot. A sweep that could not start, timed out or was
// cut is reported in the snapshot, not returned as an error.
func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.FileSweepSnapshot{
		Envelope: e.Envelope(fact.FileSweepSnapshotFact),
		Pruned:   cfg.Prune,
		Roots:    cfg.Roots,
	}

	if len(snapshot.Roots) == 0 {
		roots, err := localMounts(cfg.MountsPath, cfg.Prune)
		if err != nil {
			snapshot.Roots = []string{}
			snapshot.Status, snapshot.SweepError = fact.SweepError, err.Error()
			return e.Emit(snapshot)
		}
		snapshot.Roots = roots
	}

	uids, err := idsOf(cfg.PasswdPath)
	if err != nil {
		snapshot.Status, snapshot.SweepError = fact.SweepError, err.Error()
		return e.Emit(snapshot)
	}

	gids, err := idsOf(cfg.GroupPath)
	if err != nil {
		snapshot.Status, snapshot.SweepError = fact.SweepError, err.Error()
		return e.Emit(snapshot)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	sw := sweeper{ctx: ctx, prune: map[string]bool{}, uids: uids, gids: gids, max: cfg.MaxRecords}

	for _, p := range cfg.Prune {
		sw.prune[filepath.Clean(p)] = true
	}

	for _, root := range snapshot.Roots {
		if err := sw.walk(root); err != nil {
			break
		}
	}

	snapshot.Status = fact.SweepComplete
	switch {
	case ctx.Err() != nil:
		snapshot.Status = fact.SweepTimeout
	case sw.truncated:
		snapshot.Status = fact.SweepTruncated
	}
	snapshot.Unreadable = sw.unreadable

	for _, f := range sw.found {
		f.Envelope = e.Envelope(fact.SpecialFileFact)
		if err := e.Emit(f); err != nil {
			return err
		}
	}

	snapshot.RecordsEmitted = len(sw.found)

	// Emitted last: it tells the engine the sweep is complete.
	return e.Emit(snapshot)
}

type sweeper struct {
	ctx        context.Context
	prune      map[string]bool
	uids, gids map[int]bool
	max        int

	found      []fact.SpecialFile
	unreadable int
	truncated  bool
}

var errStop = errors.New("stop")

// walk sweeps one root without leaving its filesystem, as find -xdev.
func (sw *sweeper) walk(root string) error {

	rootInfo, err := os.Lstat(root)
	if err != nil {
		sw.unreadable++
		return nil
	}
	rootDev := deviceOf(rootInfo)

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {

		if sw.ctx.Err() != nil || sw.truncated {
			return errStop
		}

		if err != nil {
			// The directory could not be listed: what is inside was not seen.
			sw.unreadable++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() && path != root && (sw.prune[path] || isMountOf(path, rootDev)) {
			return fs.SkipDir
		}

		// Symlinks always show 0777 and point elsewhere: never judged.
		if d.Type()&fs.ModeSymlink != 0 || !(d.Type().IsRegular() || d.IsDir()) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			sw.unreadable++
			return nil
		}

		if f, special := sw.classify(path, info); special {
			if len(sw.found) >= sw.max {
				sw.truncated = true
				return errStop
			}
			sw.found = append(sw.found, f)
		}

		return nil
	})
}

// classify fills a special_file when the entry has any property op.acc.2
// looks at.
func (sw *sweeper) classify(path string, info fs.FileInfo) (fact.SpecialFile, bool) {

	mode := info.Mode()
	st, _ := info.Sys().(*syscall.Stat_t)

	f := fact.SpecialFile{
		Path:          path,
		Kind:          "file",
		SUID:          mode&fs.ModeSetuid != 0 && mode.IsRegular(),
		SGID:          mode&fs.ModeSetgid != 0 && mode.IsRegular(),
		Sticky:        mode&fs.ModeSticky != 0,
		WorldWritable: mode.Perm()&0o002 != 0,
	}

	if info.IsDir() {
		f.Kind = "directory"
	}

	if st != nil {
		f.UID, f.GID = int(st.Uid), int(st.Gid)
		f.NoOwner, f.NoGroup = !sw.uids[f.UID], !sw.gids[f.GID]
	}

	f.Mode = fmt.Sprintf("%04o", octalMode(mode))

	return f, f.SUID || f.SGID || f.WorldWritable || f.NoOwner || f.NoGroup
}

// octalMode turns Go's mode bits back into the classic 4-digit octal form.
func octalMode(mode fs.FileMode) uint32 {

	m := uint32(mode.Perm())

	if mode&fs.ModeSetuid != 0 {
		m |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		m |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		m |= 0o1000
	}

	return m
}

func deviceOf(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}

// isMountOf: a directory on another device is another filesystem.
func isMountOf(path string, rootDev uint64) bool {
	info, err := os.Lstat(path)
	return err == nil && deviceOf(info) != rootDev
}

// localMounts reads the mount table and keeps local filesystems that are not
// under a pruned directory, sorted.
func localMounts(path string, prune []string) ([]string, error) {

	file, err := fsread.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	seen := map[string]bool{}
	var roots []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		// The mount table escapes spaces and tabs as \040 and \011.
		mount := unescapeMount(fields[1])

		// "/" is the system itself whatever its type (overlay in a
		// container); other mounts only when they are local disks.
		if mount != "/" && !localTypes[fields[2]] {
			continue
		}

		if seen[mount] || underAny(mount, prune) || !isDir(mount) {
			continue
		}
		seen[mount] = true
		roots = append(roots, mount)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(roots) == 0 {
		return nil, fmt.Errorf("no local filesystem in %s", path)
	}

	sort.Strings(roots)

	return roots, nil
}

// isDir: bind mounts of single files (a container's /etc/hosts) are not
// filesystems to sweep.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// idsOf reads the third field (uid or gid) of every well-formed line of a
// passwd or group file.
func idsOf(path string) (map[int]bool, error) {

	file, err := fsread.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ids := map[int]bool{}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		if id, err := strconv.ParseUint(fields[2], 10, 32); err == nil {
			ids[int(id)] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// An empty file would make every file "without owner".
	if !ids[0] {
		return nil, fmt.Errorf("%s has no entry with id 0", path)
	}

	return ids, nil
}

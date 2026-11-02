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

	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	MountsPath string

	Roots []string

	Prune []string

	PasswdPath string
	GroupPath  string

	Timeout    time.Duration
	MaxRecords int
}

var DefaultPrune = []string{"/proc", "/sys", "/run", "/dev", "/snap", "/var/lib/docker", "/var/lib/containers"}

var localTypes = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "jfs": true, "f2fs": true, "reiserfs": true}

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

			sw.unreadable++
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() && path != root && (sw.prune[path] || isMountOf(path, rootDev)) {
			return fs.SkipDir
		}

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

func isMountOf(path string, rootDev uint64) bool {
	info, err := os.Lstat(path)
	return err == nil && deviceOf(info) != rootDev
}

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

		mount := unescapeMount(fields[1])

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

	if !ids[0] {
		return nil, fmt.Errorf("%s has no entry with id 0", path)
	}

	return ids, nil
}

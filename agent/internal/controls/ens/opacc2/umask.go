package opacc2

import (
	"bufio"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// UmaskConfig lists where the system-wide umask is declared.
type UmaskConfig struct {
	// Files are read when they exist; ProfileDir adds its *.sh files.
	Files      []string
	ProfileDir string
}

// DefaultUmaskFiles are the sources v1 read on Debian and Ubuntu.
var DefaultUmaskFiles = []string{"/etc/login.defs", "/etc/profile", "/etc/bash.bashrc"}

var octalUmask = regexp.MustCompile(`^[0-7]{1,4}$`)

// CollectUmask emits one umask_snapshot with every declaration found.
func CollectUmask(e *emit.Emitter, cfg UmaskConfig) error {

	paths := append([]string(nil), cfg.Files...)

	if cfg.ProfileDir != "" {
		scripts, _ := filepath.Glob(filepath.Join(cfg.ProfileDir, "*.sh"))
		sort.Strings(scripts)
		paths = append(paths, scripts...)
	}

	snapshot := fact.UmaskSnapshot{Envelope: e.Envelope(fact.UmaskSnapshotFact), Sources: []fact.UmaskSource{}}

	for _, path := range paths {
		snapshot.Sources = append(snapshot.Sources, readUmask(path))
	}

	return e.Emit(snapshot)
}

// umaskDecl finds "umask VALUE" anywhere in a line, as a command after a
// separator too ("[ $UID -gt 199 ] && umask 002"), and the UMASK key of
// login.defs. v1 only looked at the first word and missed those.
var umaskDecl = regexp.MustCompile(`(?i)(?:^|[\s;&|(])umask\s+([^\s;&|)]+)`)

// readUmask lists the umask declarations of one file. A bare "umask" is a
// query and "umask -S" prints: neither declares anything.
func readUmask(path string) fact.UmaskSource {

	src := fact.UmaskSource{Path: path, Status: fact.SourceRead, Umasks: []string{}}

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		return fact.UmaskSource{Path: path, Status: fact.SourceAbsent}
	}

	if err != nil {
		return fact.UmaskSource{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		line, _, _ := strings.Cut(scanner.Text(), "#")

		for _, m := range umaskDecl.FindAllStringSubmatch(line, -1) {

			value := m[1]

			if strings.HasPrefix(value, "-") {
				continue
			}

			if !octalUmask.MatchString(value) {
				src.Uninterpretable = append(src.Uninterpretable, value)
				continue
			}

			n, _ := strconv.ParseUint(value, 8, 32)
			src.Umasks = append(src.Umasks, leftPad(strconv.FormatUint(n, 8), 3))
		}
	}

	if err := scanner.Err(); err != nil {
		return fact.UmaskSource{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	return src
}

func leftPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

package settings

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/host"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

type Config struct {
	Files []string

	SSHD string
}

var DefaultFiles = []string{
	"/etc/login.defs",
	"/etc/security/faillock.conf",
	"/etc/security/pwquality.conf",
	"/etc/security/pwquality.conf.d/*.conf",
	"/etc/security/pwhistory.conf",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*.conf",
	"/etc/samba/smb.conf",
	"/etc/vsftpd.conf",
}

// Only the keys the controls judge leave the machine: configuration files can hold secrets.
var Keys = map[string][]string{
	"/etc/login.defs":              {"PASS_MAX_DAYS", "UID_MIN"},
	"/etc/security/faillock.conf":  {"deny", "unlock_time"},
	"/etc/security/pwquality.conf": {"minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit", "dictcheck"},
	"/etc/security/pwhistory.conf": {"remember"},
	"/etc/ssh/sshd_config":         {"Match"},
	"/etc/samba/smb.conf":          {"guest ok", "public"},
	"/etc/vsftpd.conf":             {"anonymous_enable"},
	"sshd -T": {"passwordauthentication", "kbdinteractiveauthentication", "usepam", "pubkeyauthentication",
		"pubkeyauthoptions", "authenticationmethods", "loglevel", "debianbanner", "versionaddendum", "banner"},
}

func keep(source string, entries []fact.ConfigEntry) []fact.ConfigEntry {

	set := Keys[source]
	for main, keys := range Keys {
		if strings.HasPrefix(source, main+".d/") {
			set = keys
		}
	}

	out := []fact.ConfigEntry{}
	for _, e := range entries {
		for _, k := range set {
			if strings.EqualFold(e.Key, k) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

const maxEntries = 500

func Collect(e *emit.Emitter, cfg Config) error {

	var sources []fact.ConfigFile

	for _, pattern := range cfg.Files {

		if !strings.Contains(pattern, "*") {
			sources = append(sources, readConfigFile(pattern))
			continue
		}

		paths, _ := filepath.Glob(pattern)
		sort.Strings(paths)

		for _, path := range paths {
			sources = append(sources, readConfigFile(path))
		}
	}

	if cfg.SSHD != "" {
		sources = append(sources, sshdEffective(cfg.SSHD), sshVersion(cfg.SSHD))
	}

	snapshot := fact.ConfigSnapshot{Envelope: e.Envelope(fact.ConfigSnapshotFact)}

	for _, src := range sources {

		src.Envelope = e.Envelope(fact.ConfigFileFact)

		if err := e.Emit(src); err != nil {
			return err
		}
		snapshot.RecordsEmitted++
	}

	return e.Emit(snapshot)
}

func readConfigFile(path string) fact.ConfigFile {

	src := fact.ConfigFile{Source: path, Kind: fact.ConfigKindFile, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		src.Status = fact.SourceAbsent
		return src
	}

	if err != nil {
		src.Status, src.Error = fact.SourceUnreadable, err.Error()
		return src
	}

	defer file.Close()

	entries, err := parseEntries(file, iniKeys(path))

	if err != nil {
		src.Status, src.Error = fact.SourceUnreadable, err.Error()
		return src
	}

	src.Entries = keep(path, entries)
	return src
}

func parseEntries(r io.Reader, ini bool) ([]fact.ConfigEntry, error) {

	entries := []fact.ConfigEntry{}
	section := ""
	n := 0

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {

		n++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}

		key, value := splitEntry(line)
		if ini {
			key, value = splitINI(line)
		}

		if strings.EqualFold(key, "match") {
			entries = append(entries, fact.ConfigEntry{Key: key, Value: value, Line: n})
			section = "Match " + value
			continue
		}

		if len(entries) == maxEntries {
			return nil, fmt.Errorf("more than %d settings", maxEntries)
		}

		entries = append(entries, fact.ConfigEntry{Key: key, Value: value, Line: n, Section: section})
	}

	return entries, scanner.Err()
}

func iniKeys(path string) bool {
	return strings.HasSuffix(path, "smb.conf")
}

func splitINI(line string) (key, value string) {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return strings.TrimSpace(line), ""
	}
	return strings.Join(strings.Fields(k), " "), strings.TrimSpace(v)
}

func splitEntry(line string) (key, value string) {

	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return line, ""
	}

	key = line[:end]
	rest := strings.TrimSpace(line[end:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))

	return key, rest
}

func sshdEffective(sshd string) fact.ConfigFile {

	src := fact.ConfigFile{Source: sshd + " -T", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}

	if _, err := os.Stat(sshd); errors.Is(err, fs.ErrNotExist) {
		src.Status = fact.SourceAbsent
		return src
	}

	out, err := host.Run(sshd, "-T")

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	entries, err := parseEntries(strings.NewReader(out), false)

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	src.Entries = keep("sshd -T", entries)
	return src
}

func sshVersion(sshd string) fact.ConfigFile {

	ssh := filepath.Join(filepath.Dir(filepath.Dir(sshd)), "bin", "ssh")
	src := fact.ConfigFile{Source: ssh + " -V", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}

	if _, err := os.Stat(ssh); errors.Is(err, fs.ErrNotExist) {
		src.Status = fact.SourceAbsent
		return src
	}

	out, err := host.Run(ssh, "-V")

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	src.Entries = append(src.Entries, fact.ConfigEntry{Key: "version", Value: strings.TrimSpace(out)})
	return src
}

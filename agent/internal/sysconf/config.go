// Package sysconf reads system configuration as facts: key/value settings of
// configuration files and programs, and the resolved PAM stacks. It only
// reports what is written; which settings matter is the engine's decision.
package sysconf

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// ConfigConfig lists the sources read by CollectConfig.
type ConfigConfig struct {
	// Files are read in order; a pattern with * is expanded and sorted, the
	// order in which programs read their drop-in directories.
	Files []string
	// SSHD is the sshd binary: its effective configuration (sshd -T) and
	// its version (ssh -V next to it) are sources too. Empty skips both.
	SSHD string
}

// DefaultConfigFiles are the files read by the controls that judge
// authentication: login.defs, faillock, pwquality, pwhistory, journald and
// sshd_config with its drop-ins (for the Match blocks sshd -T hides), and
// the services that can open access to anyone: Samba and vsftpd.
var DefaultConfigFiles = []string{
	"/etc/login.defs",
	"/etc/security/faillock.conf",
	"/etc/security/pwquality.conf",
	"/etc/security/pwquality.conf.d/*.conf",
	"/etc/security/pwhistory.conf",
	"/etc/systemd/journald.conf",
	"/etc/systemd/journald.conf.d/*.conf",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/*.conf",
	"/etc/samba/smb.conf",
	"/etc/vsftpd.conf",
}

// maxEntries bounds one source so its fact stays under the 64 KiB event
// limit of Wazuh: configuration files are far smaller.
const maxEntries = 500

// commandTimeout bounds sshd -T and ssh -V: both only parse configuration.
const commandTimeout = 10 * time.Second

// CollectConfig emits one config_file per source, then the config_snapshot.
func CollectConfig(e *emit.Emitter, cfg ConfigConfig) error {

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

// readConfigFile reads one file of "key value", "key = value" or "key=value"
// lines. [section] headers (journald) and Match blocks (sshd_config) set the
// section of the lines after them.
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

	src.Entries = entries
	return src
}

// parseEntries splits each line into key and value. The key ends at the
// first blank or "="; a "=" right after the key is dropped, so
// "minlen = 8", "Storage=none" and "PASS_MAX_DAYS 90" all read as key and
// value, and "ENV_PATH PATH=/usr/bin" keeps "PATH=/usr/bin" as the value.
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

// iniKeys: files whose keys may hold blanks ("guest ok = yes"), so the key
// ends at the "=".
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

// sshdEffective is the configuration sshd applies, Includes and defaults
// resolved: "sshd -T" prints one lowercase "key value" per line.
func sshdEffective(sshd string) fact.ConfigFile {

	src := fact.ConfigFile{Source: sshd + " -T", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}

	if _, err := os.Stat(sshd); errors.Is(err, fs.ErrNotExist) {
		src.Status = fact.SourceAbsent
		return src
	}

	out, err := runCommand(sshd, "-T")

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	entries, err := parseEntries(strings.NewReader(out), false)

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	src.Entries = entries
	return src
}

// sshVersion is the OpenSSH version, from the ssh client installed next to
// sshd: the server announces the same version before any authentication.
// It reads "ssh -V" and never connects, so no Wazuh alert is triggered.
func sshVersion(sshd string) fact.ConfigFile {

	ssh := filepath.Join(filepath.Dir(filepath.Dir(sshd)), "bin", "ssh")
	src := fact.ConfigFile{Source: ssh + " -V", Kind: fact.ConfigKindCommand, Status: fact.SourceRead, Entries: []fact.ConfigEntry{}}

	if _, err := os.Stat(ssh); errors.Is(err, fs.ErrNotExist) {
		src.Status = fact.SourceAbsent
		return src
	}

	out, err := runCommand(ssh, "-V")

	if err != nil {
		src.Status, src.Error = fact.SourceError, err.Error()
		return src
	}

	src.Entries = append(src.Entries, fact.ConfigEntry{Key: "version", Value: strings.TrimSpace(out)})
	return src
}

// runCommand returns stdout and stderr together: ssh -V prints to stderr.
func runCommand(name string, args ...string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()

	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return string(out), nil
}

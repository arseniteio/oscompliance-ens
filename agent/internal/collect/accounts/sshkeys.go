package accounts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// sshdKeys is what sshd -T says about where public keys live.
type sshdKeys struct {
	status string   // one of the fact.SSHD* values
	err    string   // set when status is fact.SSHDError
	files  []string // global AuthorizedKeysFile patterns, when status is fact.SSHDRead
	path   string   // the sshd binary, asked again per account for Match blocks
	// global: no Match block in the sshd configuration, so the global
	// files apply to every account and sshd is not asked per account
	// (thousands of accounts would take hours).
	global bool
}

// sshdConfigs are the files a Match block can be in.
var sshdConfigs = []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"}

// hasMatch: a Match line in any sshd configuration file, or one that cannot
// be read (then every account is asked, as before).
func hasMatch(patterns []string) bool {

	for _, pattern := range patterns {
		paths, _ := filepath.Glob(pattern)
		for _, p := range paths {
			data, err := fsread.ReadFile(p)
			if err != nil {
				return true
			}
			for _, line := range strings.Split(string(data), "\n") {
				if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], "match") {
					return true
				}
			}
		}
	}

	return false
}

// sshdTimeout bounds sshd -T: it only parses its configuration.
const sshdTimeout = 10 * time.Second

// readSSHD asks sshd for its effective global configuration: whether it
// exists and where it looks for keys outside any Match block.
func readSSHD(path string) sshdKeys {

	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return sshdKeys{status: fact.SSHDAbsent}
	}

	files, command, err := sshdT(path)

	switch {
	case err != nil:
		return sshdKeys{status: fact.SSHDError, err: err.Error()}
	case command:
		return sshdKeys{status: fact.SSHDCommand}
	}

	return sshdKeys{status: fact.SSHDRead, files: files, path: path, global: !hasMatch(sshdConfigs)}
}

// sshdT runs sshd -T with extra arguments and returns the AuthorizedKeysFile
// patterns, and whether an AuthorizedKeysCommand decides instead: then keys
// come from a program (LDAP, a vault...) and cannot be counted from files.
func sshdT(path string, args ...string) (files []string, command bool, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), sshdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, append([]string{"-T"}, args...)...).Output()

	if err != nil {
		return nil, false, fmt.Errorf("%s -T %s: %w", path, strings.Join(args, " "), err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	for scanner.Scan() {

		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "authorizedkeysfile":
			files = fields[1:]
		case "authorizedkeyscommand":
			if fields[1] != "none" {
				return nil, true, nil
			}
		}
	}

	return files, false, nil
}

// matchSpec is the connection sshd -T -C evaluates Match blocks against. Only
// the user is real: Match User and Match Group apply exactly, Match Address
// and Match Host as for a local connection.
func matchSpec(user string) string {
	return "user=" + user + ",host=localhost,addr=127.0.0.1"
}

// keyInfo is what EV-02 reports about one account's keys.
type keyInfo struct {
	// count is nil when the number of keys cannot be known.
	count *int
	// changed is the newest modification time of the key files, zero when
	// none exists or it cannot be known.
	changed time.Time
}

// count returns how many keys sshd would accept for the account, or nil when
// that cannot be known.
func (k sshdKeys) count(entry passwdEntry) *int {
	return k.inspect(entry).count
}

// inspect counts the keys sshd would accept for the account and when its
// key files last changed.
func (k sshdKeys) inspect(entry passwdEntry) keyInfo {

	total := 0

	switch k.status {
	case fact.SSHDAbsent:
		return keyInfo{count: &total}
	case fact.SSHDRead:
	default:
		return keyInfo{}
	}

	// Match blocks can give one account other key files, or a command.
	files, command, err := k.files, false, error(nil)
	if !k.global {
		files, command, err = sshdT(k.path, "-C", matchSpec(entry.user))
	}

	if err != nil || command {
		return keyInfo{}
	}

	var changed time.Time

	for _, pattern := range files {

		if pattern == "none" {
			continue
		}

		path := keyFilePath(pattern, entry)
		n, err := countKeyLines(path)

		if err != nil {
			return keyInfo{}
		}

		total += n

		if info, err := os.Stat(path); err == nil && n > 0 && info.ModTime().After(changed) {
			changed = info.ModTime()
		}
	}

	return keyInfo{count: &total, changed: changed}
}

// keyFilePath expands the sshd tokens %%, %h, %u and %U; a relative path is
// relative to the home directory, as sshd does.
func keyFilePath(pattern string, entry passwdEntry) string {

	replacer := strings.NewReplacer("%%", "%", "%h", entry.home, "%u", entry.user, "%U", strconv.Itoa(entry.uid))
	path := replacer.Replace(pattern)

	if !filepath.IsAbs(path) {
		path = filepath.Join(entry.home, path)
	}

	return path
}

// countKeyLines counts non-empty, non-comment lines. A missing file has no
// keys; any other error means the count is unknown.
func countKeyLines(path string) (int, error) {

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}

	if err != nil {
		return 0, err
	}

	defer file.Close()

	n := 0

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // certificate lines can be long

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}

	return n, scanner.Err()
}

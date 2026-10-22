package opacc1

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// sshdKeys is what sshd -T says about where public keys live.
type sshdKeys struct {
	status string   // one of the fact.SSHD* values
	err    string   // set when status is fact.SSHDError
	files  []string // AuthorizedKeysFile patterns, when status is fact.SSHDRead
}

// sshdTimeout bounds sshd -T: it only parses its configuration.
const sshdTimeout = 10 * time.Second

// readSSHD asks sshd for its effective configuration. Match blocks are not
// applied: the global AuthorizedKeysFile is used for every account.
func readSSHD(path string) sshdKeys {

	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return sshdKeys{status: fact.SSHDAbsent}
	}

	ctx, cancel := context.WithTimeout(context.Background(), sshdTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, "-T").Output()

	if err != nil {
		return sshdKeys{status: fact.SSHDError, err: path + " -T: " + err.Error()}
	}

	keys := sshdKeys{status: fact.SSHDRead}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	for scanner.Scan() {

		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "authorizedkeysfile":
			keys.files = fields[1:]
		case "authorizedkeyscommand":
			// Keys come from a program (LDAP, a vault...): they cannot be
			// counted from files.
			if fields[1] != "none" {
				return sshdKeys{status: fact.SSHDCommand}
			}
		}
	}

	return keys
}

// count returns how many keys sshd would accept for the account, or nil when
// that cannot be known.
func (k sshdKeys) count(entry passwdEntry) *int {

	total := 0

	switch k.status {
	case fact.SSHDAbsent:
		return &total
	case fact.SSHDRead:
	default:
		return nil
	}

	for _, pattern := range k.files {

		if pattern == "none" {
			continue
		}

		n, err := countKeyLines(keyFilePath(pattern, entry))

		if err != nil {
			return nil
		}

		total += n
	}

	return &total
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

	file, err := os.Open(path)

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

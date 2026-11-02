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

	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type sshdKeys struct {
	status string
	err    string
	files  []string
	path   string

	global bool
}

var sshdConfigs = []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"}

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

const sshdTimeout = 10 * time.Second

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

func matchSpec(user string) string {
	return "user=" + user + ",host=localhost,addr=127.0.0.1"
}

type keyInfo struct {
	count *int

	changed time.Time
}

func (k sshdKeys) inspect(entry passwdEntry) keyInfo {

	total := 0

	switch k.status {
	case fact.SSHDAbsent:
		return keyInfo{count: &total}
	case fact.SSHDRead:
	default:
		return keyInfo{}
	}

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

func keyFilePath(pattern string, entry passwdEntry) string {

	replacer := strings.NewReplacer("%%", "%", "%h", entry.home, "%u", entry.user, "%U", strconv.Itoa(entry.uid))
	path := replacer.Replace(pattern)

	if !filepath.IsAbs(path) {
		path = filepath.Join(entry.home, path)
	}

	return path
}

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
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}

	return n, scanner.Err()
}

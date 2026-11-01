package accounts

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
)

type passwdEntry struct {
	user  string
	uid   int
	gid   int
	home  string
	shell string
}

func readPasswd(path string) ([]passwdEntry, error) {

	file, err := fsread.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	var entries []passwdEntry

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" {
			continue
		}

		uid, err := parseID(fields[2])

		if err != nil {
			continue
		}

		gid, err := parseID(fields[3])

		if err != nil {
			continue
		}

		entries = append(entries, passwdEntry{
			user:  fields[0],
			uid:   uid,
			gid:   gid,
			home:  fields[5],
			shell: fields[6],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return entries, nil
}

func parseID(s string) (int, error) {

	id, err := strconv.ParseUint(s, 10, 32)

	if err != nil {
		return 0, err
	}

	return int(id), nil
}

func hasRoot(entries []passwdEntry) bool {

	for _, entry := range entries {
		if entry.uid == 0 {
			return true
		}
	}

	return false
}

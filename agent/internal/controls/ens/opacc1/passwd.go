// Package opacc1 collects the facts of ENS control op.acc.1.
package opacc1

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// passwdEntry is one well-formed line of the account database.
type passwdEntry struct {
	user  string
	uid   int
	gid   int
	home  string
	shell string
}

// readPasswd parses the whole file before anything is emitted, so that a read
// error halfway never leaves records without their snapshot. Lines that are not
// a well-formed passwd entry are skipped, as v1 did.
func readPasswd(path string) ([]passwdEntry, error) {

	file, err := os.Open(path)

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

	// Covers I/O errors and paths that are not regular files, like a directory.
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return entries, nil
}

// parseID accepts only unsigned decimal IDs: Atoi would also take "-1" and "+5".
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

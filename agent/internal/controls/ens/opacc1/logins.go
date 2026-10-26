package opacc1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"io"
	"io/fs"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// Default login record files on Linux: wtmp and its rotated copy (Debian and
// RHEL rotate it monthly), and lastlog, which keeps the last login per UID
// even after wtmp rotated away.
var (
	DefaultLoginRecords = []string{"/var/log/wtmp", "/var/log/wtmp.1"}
	DefaultLastlog      = "/var/log/lastlog"
)

// glibc utmp record on Linux (64 and 32 bit alike): 384 bytes; ut_type at 0,
// ut_user at 44 (32 bytes), ut_tv.tv_sec at 340 (int32).
const (
	utmpSize     = 384
	utmpUser     = 44
	utmpUserLen  = 32
	utmpTime     = 340
	userProcess  = 7
	lastlogSize  = 292 // int32 ll_time, char ll_line[32], char ll_host[256]
	maxLoginRead = 64 << 20
)

// readLogins returns the newest login time per account name, and which
// files were read. A file that is missing records nothing; a file that
// cannot be read is reported and skipped.
func readLogins(wtmp []string, lastlog string, entries []passwdEntry) (map[string]time.Time, []fact.LoginRecordFile) {

	last := map[string]time.Time{}
	var sources []fact.LoginRecordFile

	newer := func(user string, t time.Time) {
		if t.After(last[user]) {
			last[user] = t
		}
	}

	for _, path := range wtmp {
		sources = append(sources, readWtmp(path, newer))
	}

	if lastlog != "" {
		sources = append(sources, readLastlog(lastlog, entries, newer))
	}

	return last, sources
}

// readWtmp reads every USER_PROCESS record: one per interactive login.
func readWtmp(path string, newer func(string, time.Time)) fact.LoginRecordFile {

	data, status := readRecordFile(path)

	if status.Status != fact.SourceRead {
		return status
	}

	for off := 0; off+utmpSize <= len(data); off += utmpSize {

		rec := data[off : off+utmpSize]

		if int16(binary.LittleEndian.Uint16(rec[0:2])) != userProcess {
			continue
		}

		user := cString(rec[utmpUser : utmpUser+utmpUserLen])
		sec := int32(binary.LittleEndian.Uint32(rec[utmpTime : utmpTime+4]))

		if user != "" && sec > 0 {
			newer(user, time.Unix(int64(sec), 0))
		}
	}

	return status
}

// readLastlog reads the record of each account's UID; lastlog is a sparse
// file indexed by UID.
func readLastlog(path string, entries []passwdEntry, newer func(string, time.Time)) fact.LoginRecordFile {

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		return fact.LoginRecordFile{Path: path, Status: fact.SourceAbsent}
	}

	if err != nil {
		return fact.LoginRecordFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	defer file.Close()

	buf := make([]byte, 4)

	for _, entry := range entries {

		_, err := file.ReadAt(buf, int64(entry.uid)*lastlogSize)

		if errors.Is(err, io.EOF) {
			continue
		}

		if err != nil {
			return fact.LoginRecordFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
		}

		if sec := int32(binary.LittleEndian.Uint32(buf)); sec > 0 {
			newer(entry.user, time.Unix(int64(sec), 0))
		}
	}

	return fact.LoginRecordFile{Path: path, Status: fact.SourceRead}
}

// readRecordFile reads a whole wtmp file, bounded: wtmp grows with every
// login, a bigger one is cut to its newest records.
func readRecordFile(path string) ([]byte, fact.LoginRecordFile) {

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		return nil, fact.LoginRecordFile{Path: path, Status: fact.SourceAbsent}
	}

	if err != nil {
		return nil, fact.LoginRecordFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fact.LoginRecordFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	start := int64(0)
	if size := info.Size(); size > maxLoginRead {
		start = (size - maxLoginRead) / utmpSize * utmpSize
	}

	data, err := io.ReadAll(io.NewSectionReader(file, start, info.Size()-start))
	if err != nil {
		return nil, fact.LoginRecordFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()}
	}

	return data, fact.LoginRecordFile{Path: path, Status: fact.SourceRead}
}

// cString is a NUL-terminated fixed-size C string.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

package opacc1

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

func utmpRecord(kind int16, user string, sec int32) []byte {
	rec := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(rec[0:2], uint16(kind))
	copy(rec[utmpUser:utmpUser+utmpUserLen], user)
	binary.LittleEndian.PutUint32(rec[utmpTime:utmpTime+4], uint32(sec))
	return rec
}

func TestReadLogins(t *testing.T) {

	dir := t.TempDir()

	var wtmp []byte
	wtmp = append(wtmp, utmpRecord(userProcess, "ana", 1_700_000_000)...)
	wtmp = append(wtmp, utmpRecord(8, "ana", 1_800_000_000)...) // DEAD_PROCESS: a logout, not a login
	wtmp = append(wtmp, utmpRecord(userProcess, "ana", 1_750_000_000)...)
	wtmp = append(wtmp, utmpRecord(userProcess, "bob", 1_600_000_000)...)
	if err := os.WriteFile(filepath.Join(dir, "wtmp"), wtmp, 0o644); err != nil {
		t.Fatal(err)
	}

	// lastlog: bob (uid 1001) logged in later than wtmp remembers.
	lastlog := make([]byte, 1002*lastlogSize)
	binary.LittleEndian.PutUint32(lastlog[1001*lastlogSize:], 1_650_000_000)
	if err := os.WriteFile(filepath.Join(dir, "lastlog"), lastlog, 0o644); err != nil {
		t.Fatal(err)
	}

	entries := []passwdEntry{{user: "ana", uid: 1000}, {user: "bob", uid: 1001}, {user: "eve", uid: 5000}}

	got, sources := readLogins([]string{filepath.Join(dir, "wtmp"), filepath.Join(dir, "wtmp.1")}, filepath.Join(dir, "lastlog"), entries)

	if !got["ana"].Equal(time.Unix(1_750_000_000, 0)) || !got["bob"].Equal(time.Unix(1_650_000_000, 0)) {
		t.Errorf("last logins: %v", got)
	}
	if _, ok := got["eve"]; ok {
		t.Errorf("eve never logged in: %v", got["eve"])
	}

	want := []string{fact.SourceRead, fact.SourceAbsent, fact.SourceRead}
	for i, s := range sources {
		if s.Status != want[i] {
			t.Errorf("source %s: %s, want %s", s.Path, s.Status, want[i])
		}
	}
}

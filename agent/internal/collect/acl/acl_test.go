package acl

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func TestCollectACL(t *testing.T) {

	dir := t.TempDir()
	datos := filepath.Join(dir, "datos")
	if err := os.Mkdir(datos, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(datos, 0o750); err != nil {
		t.Fatal(err)
	}
	collecttest.Write(t, filepath.Join(dir, "oscompliance.json"), `{"acl_paths":["`+datos+`","`+filepath.Join(dir, "missing")+`"]}`)

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{SharedPaths: filepath.Join(dir, "oscompliance.json")})
	})

	if len(facts) != 3 || facts[0]["mode"] != "0750" || facts[0]["acl"] == nil || facts[1]["status"] != "absent" || facts[2]["records_emitted"] != 2.0 {
		t.Errorf("acl: %v", facts)
	}

	facts = collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{SharedPaths: filepath.Join(dir, "none.json")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("no shared file: %v", facts)
	}
}

func TestParseACL(t *testing.T) {

	entry := func(tag, perm uint16, id uint32) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b, tag)
		binary.LittleEndian.PutUint16(b[2:], perm)
		binary.LittleEndian.PutUint32(b[4:], id)
		return b
	}

	data := []byte{2, 0, 0, 0}
	data = append(data, entry(aclUserObj, 7, 0)...)
	data = append(data, entry(aclUser, 5, 4242424)...)
	data = append(data, entry(aclGroupObj, 5, 0)...)
	data = append(data, entry(aclMask, 5, 0)...)
	data = append(data, entry(aclOther, 0, 0)...)

	got, err := parseACL(data, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "u:4242424:r-x,m::r-x" {
		t.Errorf("access ACL: %v", got)
	}

	got, _ = parseACL(data, "d:", true)
	if len(got) != 5 || got[0] != "d:u::rwx" || got[4] != "d:o::---" {
		t.Errorf("default ACL: %v", got)
	}

	if _, err := parseACL([]byte{1, 0, 0, 0}, "", false); err == nil {
		t.Error("bad version must fail")
	}
}

package acl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"sort"
	"strconv"
	"syscall"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	Wazuh wazuh.AgentConfigPaths
}

func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.ACLSnapshot{Envelope: e.Envelope(fact.ACLSnapshotFact), Config: cfg.Wazuh.SharedConf, Status: fact.SourceRead}

	paths, ok, err := wazuh.ReadSharedPaths(cfg.Wazuh)

	switch {
	case err != nil:
		snapshot.Status, snapshot.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	case !ok:
		snapshot.Status = fact.SourceAbsent
		return e.Emit(snapshot)
	}

	for _, p := range paths.ACLPaths {

		record := readACL(p)
		record.Envelope = e.Envelope(fact.ACLRecordFact)

		if err := e.Emit(record); err != nil {
			return err
		}
		snapshot.RecordsEmitted++
	}

	return e.Emit(snapshot)
}

func readACL(path string) fact.ACLRecord {

	r := fact.ACLRecord{Path: path, Status: fact.SourceRead}

	info, err := os.Stat(path)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.Status = fact.SourceAbsent
		return r
	case err != nil:
		r.Status, r.Error = fact.SourceUnreadable, err.Error()
		return r
	}

	r.Mode = fmt.Sprintf("%04o", uint32(info.Mode().Perm())|specialBits(info.Mode()))

	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		r.Owner = userName(st.Uid) + ":" + groupName(st.Gid)
	}

	acl, err := extendedACL(path, info.IsDir())
	if err != nil {
		r.Status, r.Error = fact.SourceUnreadable, err.Error()
		return r
	}
	r.ACL = acl

	return r
}

func specialBits(m fs.FileMode) uint32 {
	var bits uint32
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

func userName(uid uint32) string {
	if u, err := user.LookupId(strconv.Itoa(int(uid))); err == nil {
		return u.Username
	}
	return strconv.Itoa(int(uid))
}

func groupName(gid uint32) string {
	if g, err := user.LookupGroupId(strconv.Itoa(int(gid))); err == nil {
		return g.Name
	}
	return strconv.Itoa(int(gid))
}

const (
	aclVersion  = 2
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
)

func parseACL(data []byte, prefix string, base bool) ([]string, error) {

	if len(data) < 4 || binary.LittleEndian.Uint32(data) != aclVersion || (len(data)-4)%8 != 0 {
		return nil, fmt.Errorf("unexpected ACL attribute of %d bytes", len(data))
	}

	var out []string

	for off := 4; off < len(data); off += 8 {

		tag := binary.LittleEndian.Uint16(data[off:])
		perm := binary.LittleEndian.Uint16(data[off+2:])
		id := binary.LittleEndian.Uint32(data[off+4:])

		var entry string
		switch tag {
		case aclUser:
			entry = "u:" + userName(id)
		case aclGroup:
			entry = "g:" + groupName(id)
		case aclMask:
			entry = "m:"
		case aclUserObj:
			entry = "u:"
		case aclGroupObj:
			entry = "g:"
		case aclOther:
			entry = "o:"
		default:
			return nil, fmt.Errorf("unknown ACL tag %#x", tag)
		}

		if !base && (tag == aclUserObj || tag == aclGroupObj || tag == aclOther) {
			continue
		}

		out = append(out, prefix+entry+":"+permString(perm))
	}

	return out, nil
}

func permString(p uint16) string {
	b := []byte("---")
	if p&4 != 0 {
		b[0] = 'r'
	}
	if p&2 != 0 {
		b[1] = 'w'
	}
	if p&1 != 0 {
		b[2] = 'x'
	}
	return string(b)
}

func extendedACL(path string, dir bool) ([]string, error) {

	out := []string{}

	access, err := getACL(path, "system.posix_acl_access")
	if err != nil {
		return nil, err
	}
	if access != nil {
		entries, err := parseACL(access, "", false)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}

	if dir {
		def, err := getACL(path, "system.posix_acl_default")
		if err != nil {
			return nil, err
		}
		if def != nil {
			entries, err := parseACL(def, "d:", true)
			if err != nil {
				return nil, err
			}
			out = append(out, entries...)
		}
	}

	sort.Strings(out)
	return out, nil
}

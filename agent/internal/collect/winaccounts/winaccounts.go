package winaccounts

import (
	_ "embed"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

var (
	//go:embed identity.ps1
	identityScript string
	//go:embed groups.ps1
	groupsScript string
)

const MaxRecords = 20000

type user struct {
	Name             string `json:"name"`
	SID              string `json:"sid"`
	Enabled          bool   `json:"enabled"`
	PasswordLastSet  string `json:"password_last_set"`
	PasswordRequired bool   `json:"password_required"`
	MustChange       bool   `json:"must_change"`
	MaxDays          *int   `json:"max_days"`
	Expires          string `json:"expires"`
	LastLogon        string `json:"last_logon"`
}

type identityOutput struct {
	Source string `json:"source"`
	Users  []user `json:"users"`
}

type group struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members"`
}

type groupsOutput struct {
	Source   string  `json:"source"`
	Computer string  `json:"computer"`
	Groups   []group `json:"groups"`
}

// Windows has no primary group a judge relies on; 513 is the RID of None and Domain Users.
const primaryGroupRID = 513

func CollectIdentity(e *emit.Emitter, run winps.Runner) error {

	snapshot := fact.IdentitySnapshot{Envelope: e.Envelope(fact.IdentitySnapshotFact), PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, SSHDStatus: fact.SSHDAbsent}

	out, err := winps.Decode[identityOutput](run, identityScript)
	if err != nil {
		snapshot.PasswdPath, snapshot.ShadowPath = "sam", "sam"
		snapshot.PasswdStatus, snapshot.PasswdError = fact.SourceUnreadable, err.Error()
		snapshot.ShadowStatus, snapshot.ShadowError = fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	}
	snapshot.PasswdPath, snapshot.ShadowPath = out.Source, out.Source

	emitted := 0
	for _, u := range out.Users {
		if emitted == MaxRecords {
			break
		}
		if err := e.Emit(record(e, u)); err != nil {
			return err
		}
		emitted++
	}
	snapshot.RecordsEmitted = &emitted

	return e.Emit(snapshot)
}

func record(e *emit.Emitter, u user) fact.IdentityRecord {

	none := 0
	r := fact.IdentityRecord{Envelope: e.Envelope(fact.IdentityRecordFact), AccountName: u.Name, UID: RID(u.SID), GID: primaryGroupRID,
		PasswordState: passwordState(u), AuthorizedKeys: &none, PasswordChangeForced: u.MustChange, PasswordMaxDays: u.MaxDays}

	r.AccountExpires = day(u.Expires)
	r.PasswordChanged = day(u.PasswordLastSet)
	r.LastLogin = instant(u.LastLogon)
	return r
}

func passwordState(u user) string {
	switch {
	case !u.Enabled:
		return fact.PasswordLocked
	case u.PasswordLastSet == "" && !u.PasswordRequired:
		return fact.PasswordEmpty
	case u.PasswordLastSet == "":
		return fact.PasswordOther
	}
	return fact.PasswordSet
}

func RID(sid string) int {
	i := strings.LastIndexByte(sid, '-')
	n, err := strconv.Atoi(sid[i+1:])
	if i < 0 || err != nil {
		return -1
	}
	return n
}

func day(iso string) string {
	if t, ok := parse(iso); ok {
		return t.Format("2006-01-02")
	}
	return ""
}

func instant(iso string) string {
	if t, ok := parse(iso); ok {
		return t.Format(time.RFC3339)
	}
	return ""
}

func parse(iso string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, iso)
	return t.UTC(), err == nil && iso != ""
}

func CollectGroups(e *emit.Emitter, run winps.Runner) error {

	snapshot := fact.GroupSnapshot{Envelope: e.Envelope(fact.GroupSnapshotFact), GroupStatus: fact.SourceRead}

	out, err := winps.Decode[groupsOutput](run, groupsScript)
	if err != nil {
		snapshot.GroupPath, snapshot.GroupStatus, snapshot.GroupError = "sam", fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	}
	snapshot.GroupPath = out.Source

	emitted := 0
	for _, g := range out.Groups {
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, Member(m, out.Computer))
		}
		if err := e.Emit(fact.GroupRecord{Envelope: e.Envelope(fact.GroupRecordFact), GroupName: g.Name, GID: RID(g.SID), Members: members}); err != nil {
			return err
		}
		emitted++
	}
	snapshot.RecordsEmitted = &emitted

	return e.Emit(snapshot)
}

// Member turns a WinNT ADsPath into the name a judge compares: a bare name for
// an account of this computer, DOMAIN\name otherwise, and the SID when it no
// longer resolves.
func Member(adsPath, computer string) string {

	parts := strings.Split(strings.TrimPrefix(adsPath, "WinNT://"), "/")
	switch {
	case len(parts) == 3 && strings.EqualFold(parts[1], computer):
		return parts[2]
	case len(parts) == 3:
		return parts[1] + `\` + parts[2]
	case len(parts) == 2 && strings.EqualFold(parts[0], computer):
		return parts[1]
	case len(parts) == 2:
		return parts[0] + `\` + parts[1]
	}
	return parts[0]
}

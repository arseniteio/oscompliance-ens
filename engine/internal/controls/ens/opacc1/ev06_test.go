package opacc1

import (
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func groupPass(groups ...fact.GroupRecord) (*fact.GroupSnapshot, []fact.GroupRecord) {
	n := len(groups)
	return &fact.GroupSnapshot{Envelope: fact.Envelope{RunID: "g1"}, GroupPath: "/etc/group", GroupStatus: fact.SourceRead, RecordsEmitted: &n}, groups
}

func group(name string, members ...string) fact.GroupRecord {
	if members == nil {
		members = []string{}
	}
	return fact.GroupRecord{GroupName: name, Members: members}
}

func TestJudgeEV06(t *testing.T) {
	base := func(groups ...fact.GroupRecord) EV06Input {
		snapshot, records := groupPass(groups...)
		return EV06Input{
			Groups: snapshot, GroupRecords: records,
			Accounts:   []string{"root", "ubuntu", "jperez", "jperez.adm", "mgarcia"},
			Privileged: DefaultPrivilegedGroups, Suffix: ".adm", AuthSeen: true,
		}
	}

	withLogins := func(in EV06Input, accounts ...string) EV06Input {
		for _, a := range accounts {
			in.Logins = append(in.Logins, source.Login{Account: a})
		}
		return in
	}

	unread := base()
	unread.Groups = &fact.GroupSnapshot{GroupPath: "/etc/group", GroupStatus: fact.SourceUnreadable, GroupError: "denied"}

	incomplete := base(group("sudo"))
	two := 2
	incomplete.Groups.RecordsEmitted = &two

	noAccounts := base(group("sudo", "ubuntu"))
	noAccounts.Accounts, noAccounts.AccountsProblem = nil, catalog.Says("opacc1.no_identity_pass_lookback")

	badP11 := base()
	badP11.ConfigProblem = catalog.Says("param.invalid", "param", "P-11", "error", "regex not supported")

	silent := base(group("sudo", "jperez.adm"))
	silent.AuthSeen = false

	silentWithFinding := base(group("sudo", "ubuntu"))
	silentWithFinding.AuthSeen = false

	noSuffix := base(group("sudo", "jperez"))
	noSuffix.Suffix = ""

	defaulted := base(group("sudo", "jperez.adm"))
	defaulted.PrivilegedDefault = true

	cases := []struct {
		name    string
		in      EV06Input
		status  verdict.Status
		cause   verdict.Cause
		reasons []string
	}{
		{"P-11 unusable", badP11, verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-11"}},
		{"no group snapshot", EV06Input{Privileged: DefaultPrivilegedGroups}, verdict.NotEvaluable, verdict.CauseCollection, nil},
		{"group file unread", unread, verdict.NotEvaluable, verdict.CauseCollection, []string{"denied"}},
		{"incomplete group pass", incomplete, verdict.NotEvaluable, verdict.CauseCollection, []string{"1 of 2"}},
		{"account list unavailable", noAccounts, verdict.NotEvaluable, verdict.CauseCollection, []string{"no complete identity pass"}},
		{"privileged member without admin identity", base(group("sudo", "ubuntu"), group("adm", "ubuntu")), verdict.NonCompliant, "", []string{"no separate admin identity: ubuntu (sudo)"}},
		{"admin identity exists", base(group("sudo", "jperez")), verdict.Compliant, "", []string{"1 members"}},
		{"admin account itself is not a finding", base(group("wheel", "jperez.adm")), verdict.Compliant, "", nil},
		{"member of two privileged groups", base(group("sudo", "mgarcia"), group("wheel", "mgarcia")), verdict.NonCompliant, "", []string{"mgarcia (sudo, wheel)"}},
		{"login with the privileged identity", withLogins(base(group("sudo", "jperez")), "jperez", "jperez", "mgarcia"), verdict.NonCompliant, "", []string{"privileged identity used to log in: jperez (2)"}},
		{"login with the admin identity is fine", withLogins(base(group("sudo", "jperez.adm")), "jperez.adm"), verdict.Compliant, "", nil},
		{"no suffix: nobody excluded", noSuffix, verdict.NonCompliant, "", []string{"jperez (sudo)"}},
		{"finding stands without auth log", silentWithFinding, verdict.NonCompliant, "", []string{"ubuntu"}},
		{"nothing found, auth log silent", silent, verdict.NotEvaluable, verdict.CauseCollection, []string{"cannot be checked"}},
		{"default P-11 is said", defaulted, verdict.Compliant, "", []string{"product default"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JudgeEV06(c.in)

			if got.Status != c.status || got.Cause != c.cause {
				t.Errorf("got %s/%s, want %s/%s (reason %q)", got.Status, got.Cause, c.status, c.cause, got.Reason)
			}
			for _, r := range c.reasons {
				if !strings.Contains(got.Reason, r) {
					t.Errorf("reason %q does not contain %q", got.Reason, r)
				}
			}
		})
	}
}

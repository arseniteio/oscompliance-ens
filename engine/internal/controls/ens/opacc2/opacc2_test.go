package opacc2

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type want struct {
	status  verdict.Status
	cause   verdict.Cause
	reasons []string
}

func check(t *testing.T, name string, got verdict.Judgement, w want) {
	t.Helper()
	if got.Status != w.status || got.Cause != w.cause {
		t.Errorf("%s: got %s/%s, want %s/%s (reason %q)", name, got.Status, got.Cause, w.status, w.cause, got.Reason)
	}
	for _, r := range w.reasons {
		if !strings.Contains(got.Reason, r) {
			t.Errorf("%s: reason %q does not contain %q", name, got.Reason, r)
		}
	}
}

func sweep(files ...fact.SpecialFile) Sweep {
	return Sweep{Snapshot: &fact.FileSweepSnapshot{Roots: []string{"/"}, Status: fact.SweepComplete, RecordsEmitted: len(files)}, Files: files}
}

func ww(path, mode string, dir, sticky bool) fact.SpecialFile {
	kind := "file"
	if dir {
		kind = "directory"
	}
	return fact.SpecialFile{Path: path, Kind: kind, Mode: mode, WorldWritable: true, Sticky: sticky}
}

func umasks(values ...string) *fact.UmaskSnapshot {
	return &fact.UmaskSnapshot{Sources: []fact.UmaskSource{
		{Path: "/etc/login.defs", Status: fact.SourceRead, Umasks: values},
		{Path: "/etc/profile", Status: fact.SourceAbsent},
	}}
}

func TestJudgeEV01(t *testing.T) {
	scope := []string{"/etc", "/srv/data"}

	base := func(s Sweep, u *fact.UmaskSnapshot) EV01Input {
		return EV01Input{Sweep: s, Umask: u, Scope: scope, Exceptions: []string{"/srv/data/drop"}, MinUmask: "027"}
	}

	sticky := base(sweep(ww("/srv/data/tmp", "1777", true, true)), umasks("027"))
	sticky.StickyAllowed = true

	partial := base(sweep(), umasks("027"))
	partial.Sweep.Snapshot.Unreadable = 2

	timedOut := base(sweep(ww("/etc/x", "0666", false, false)), umasks("027"))
	timedOut.Sweep.Snapshot.Status = fact.SweepTimeout

	symbolic := base(sweep(), &fact.UmaskSnapshot{Sources: []fact.UmaskSource{{Path: "/etc/profile", Status: fact.SourceRead, Umasks: []string{"027"}, Uninterpretable: []string{"u=rwx"}}}})

	badP07 := base(sweep(), umasks("027"))
	badP07.MinUmask = "abc"

	config := base(sweep(), umasks("027"))
	config.ConfigProblem = catalog.Says("param.not_set", "param", "P-02")

	cases := map[string]struct {
		in EV01Input
		w  want
	}{
		"config":                        {config, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-02"}}},
		"P-07 not octal":                {badP07, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-07"}}},
		"no sweep":                      {base(Sweep{}, umasks("027")), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"file_sweep_snapshot"}}},
		"no umask facts":                {base(sweep(), nil), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"umask_snapshot"}}},
		"clean":                         {base(sweep(), umasks("027", "077")), want{verdict.Compliant, "", []string{"2 umask declarations"}}},
		"world-writable in scope":       {base(sweep(ww("/etc/shadow-", "0666", false, false)), umasks("027")), want{verdict.NonCompliant, "", []string{"/etc/shadow- (0666)"}}},
		"outside scope ignored":         {base(sweep(ww("/tmp", "1777", true, true), ww("/etcetera/x", "0666", false, false)), umasks("027")), want{verdict.Compliant, "", nil}},
		"exception by exact path":       {base(sweep(ww("/srv/data/drop", "0777", true, false)), umasks("027")), want{verdict.Compliant, "", nil}},
		"sticky not allowed by default": {base(sweep(ww("/srv/data/tmp", "1777", true, true)), umasks("027")), want{verdict.NonCompliant, "", []string{"/srv/data/tmp"}}},
		"sticky allowed by P-03":        {sticky, want{verdict.Compliant, "", nil}},
		"umask bitwise, not numeric":    {base(sweep(), umasks("032")), want{verdict.NonCompliant, "", []string{"umask 032"}}},
		"weak umask":                    {base(sweep(), umasks("022")), want{verdict.NonCompliant, "", []string{"weaker than 027"}}},
		"partial sweep, nothing found":  {partial, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"2 directories"}}},
		"finding stands on a timeout":   {timedOut, want{verdict.NonCompliant, "", []string{"/etc/x"}}},
		"symbolic umask":                {symbolic, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"not octal"}}},
		"no declaration":                {base(sweep(), umasks()), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"no source declares"}}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV01(c.in), c.w)
	}
}

func suid(path string) fact.SpecialFile {
	return fact.SpecialFile{Path: path, Kind: "file", Mode: "4755", SUID: true}
}

func TestJudgeEV07(t *testing.T) {
	baseline := []string{"/usr/bin/sudo", "/usr/bin/passwd"}

	unowned := fact.SpecialFile{Path: "/opt/app/bin", Kind: "file", Mode: "0755", UID: 1500, GID: 1500, NoOwner: true, NoGroup: true}

	timedOut := EV07Input{Sweep: sweep(suid("/usr/bin/sudo")), Authorized: baseline}
	timedOut.Sweep.Snapshot.Status = fact.SweepTimeout

	cases := map[string]struct {
		in EV07Input
		w  want
	}{
		"no sweep":                         {EV07Input{}, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"all reviewed":                     {EV07Input{Sweep: sweep(suid("/usr/bin/sudo"), suid("/usr/bin/passwd")), Authorized: baseline}, want{verdict.Compliant, "", []string{"2 SUID/SGID"}}},
		"unreviewed SUID":                  {EV07Input{Sweep: sweep(suid("/usr/bin/sudo"), suid("/tmp/x")), Authorized: baseline}, want{verdict.NonCompliant, "", []string{"/tmp/x (4755)"}}},
		"unowned without baseline":         {EV07Input{Sweep: sweep(unowned, suid("/usr/bin/sudo")), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.NonCompliant, "", []string{"uid 1500"}}},
		"SUID without baseline":            {EV07Input{Sweep: sweep(suid("/usr/bin/sudo")), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-10"}}},
		"no SUID needs no baseline":        {EV07Input{Sweep: sweep(), AuthorizedProblem: catalog.Says("param.not_set", "param", "P-00")}, want{verdict.Compliant, "", nil}},
		"timeout with nothing wrong found": {timedOut, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"time limit"}}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV07(c.in), c.w)
	}
}

func accounts() Accounts {
	n, g := 5, 3
	return Accounts{
		Identity: &fact.IdentitySnapshot{PasswdStatus: fact.SourceRead, ShadowStatus: fact.SourceRead, RecordsEmitted: &n},
		IdentityRecords: []fact.IdentityRecord{
			{AccountName: "root", UID: 0, GID: 0},
			{AccountName: "ana", UID: 1000, GID: 1000},
			{AccountName: "bob", UID: 1001, GID: 27},
			{AccountName: "eva", UID: 1002, GID: 1002},
			{AccountName: "ops1", UID: 1003, GID: 1003},
		},
		Groups: &fact.GroupSnapshot{GroupStatus: fact.SourceRead, RecordsEmitted: &g},
		GroupRecords: []fact.GroupRecord{
			{GroupName: "root", GID: 0, Members: []string{}},
			{GroupName: "sudo", GID: 27, Members: []string{"ana"}},
			{GroupName: "ops", GID: 1500, Members: []string{"ops1"}},
		},
	}
}

func sudoers(blind int, grants ...fact.SudoGrant) Sudoers {
	return Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceRead, BlindSpots: blind, BlindSpotReasons: []string{"/etc/sudoers:9: ALL users granted"}[:min(blind, 1)], RecordsEmitted: len(grants)}, Grants: grants}
}

func grant(kind, subject string) fact.SudoGrant {
	return fact.SudoGrant{SubjectKind: kind, Subject: subject, File: "/etc/sudoers", Line: 1}
}

func TestJudgeEV05(t *testing.T) {
	base := func(s Sudoers, declared ...string) EV05Input {
		return EV05Input{Accounts: accounts(), Sudoers: s, Groups: []string{"sudo"}, Declared: declared}
	}

	config := base(sudoers(0))
	config.ConfigProblem = catalog.Says("param.not_set", "param", "P-05")

	noGroups := base(sudoers(0))
	noGroups.Accounts.Groups = nil

	unreadable := base(sudoers(0))
	unreadable.Sudoers.Snapshot.Status = fact.SourceUnreadable

	cases := map[string]struct {
		in EV05Input
		w  want
	}{
		"config":                         {config, want{verdict.NotEvaluable, verdict.CauseConfiguration, []string{"P-05"}}},
		"no groups":                      {noGroups, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"no sudoers facts":               {EV05Input{Accounts: accounts(), Groups: []string{"sudo"}}, want{verdict.NotEvaluable, verdict.CauseCollection, []string{"sudoers_snapshot"}}},
		"sudoers unreadable":             {unreadable, want{verdict.NotEvaluable, verdict.CauseCollection, nil}},
		"all declared":                   {base(sudoers(0, grant("user", "root"), grant("group", "sudo")), "ana", "bob"), want{verdict.Compliant, "", []string{"2 privileged accounts"}}},
		"primary group member counts":    {base(sudoers(0), "ana"), want{verdict.NonCompliant, "", []string{"bob (group sudo)"}}},
		"sudo user grant":                {base(sudoers(0, grant("user", "eva")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva (sudoers /etc/sudoers:1)"}}},
		"sudo by uid":                    {base(sudoers(0, grant("uid", "1002")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva"}}},
		"sudo by gid":                    {base(sudoers(0, grant("gid", "1500")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"ops1"}}},
		"blind spots, nothing found":     {base(sudoers(1), "ana", "bob"), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"ALL users"}}},
		"blind spots do not hide a find": {base(sudoers(1, grant("user", "eva")), "ana", "bob"), want{verdict.NonCompliant, "", []string{"eva"}}},
		"unknown group":                  {base(sudoers(0, grant("group", "ghosts")), "ana", "bob"), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"%ghosts"}}},
		"no sudo installed":              {base(Sudoers{Snapshot: &fact.SudoersSnapshot{Status: fact.SourceAbsent}}, "ana", "bob"), want{verdict.Compliant, "", nil}},
	}

	for name, c := range cases {
		check(t, name, JudgeEV05(c.in), c.w)
	}
}

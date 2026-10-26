package opacc2

import (
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

func wazuhConfig(dirs ...fact.FIMDirectory) *fact.WazuhAgentConfig {
	return &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscheckFrequency: 43200, Directories: dirs, Ignored: []string{"/etc/mtab"}}
}

func TestJudgeEV02(t *testing.T) {

	etc := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	critical := []string{"/etc/passwd", "/etc/sudoers.d"}
	change := source.FIMChange{Path: "/etc/sudoers.d/90-ops", Event: "added", Time: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)}
	other := source.FIMChange{Path: "/etc/hosts", Event: "modified"}

	check(t, "unchanged", JudgeEV02(EV02Input{Config: etc, Changes: []source.FIMChange{other}, Window: 26 * time.Hour, Critical: critical}), want{verdict.Compliant, "", []string{"2 critical paths"}})
	check(t, "changed", JudgeEV02(EV02Input{Config: etc, Changes: []source.FIMChange{change}, Window: 26 * time.Hour, Critical: critical}), want{verdict.NonCompliant, "", []string{"/etc/sudoers.d/90-ops added"}})
	check(t, "not watched", JudgeEV02(EV02Input{Config: wazuhConfig(fact.FIMDirectory{Path: "/usr/bin"}), Window: 26 * time.Hour, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"/etc/passwd (no FIM directory covers it)"}})

	slow := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	slow.SyscheckFrequency = 7 * 86400
	check(t, "scans too far apart", JudgeEV02(EV02Input{Config: slow, Window: 26 * time.Hour, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"longer than the window"}})
	realtime := wazuhConfig(fact.FIMDirectory{Path: "/etc", Realtime: true})
	realtime.SyscheckFrequency = 7 * 86400
	check(t, "realtime", JudgeEV02(EV02Input{Config: realtime, Window: 26 * time.Hour, Critical: critical}), want{verdict.Compliant, "", nil})

	off := wazuhConfig(fact.FIMDirectory{Path: "/etc"})
	off.SyscheckDisabled = true
	check(t, "FIM off", JudgeEV02(EV02Input{Config: off, Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"disabled"}})
	check(t, "no config", JudgeEV02(EV02Input{Critical: critical}), want{verdict.NotEvaluable, verdict.CauseCollection, nil})
	check(t, "P-02 missing", JudgeEV02(EV02Input{CriticalProblem: "not set"}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}

func TestJudgeEV03(t *testing.T) {

	reaches := passes.AuthLog{Known: true, Reaches: true, Detail: "probe came back"}
	s := sudoers(0, grant("group", "sudo"))
	base := func(e ...source.Elevation) EV03Input {
		return EV03Input{Accounts: accounts(), Sudoers: s, Elevations: e, Log: reaches, Groups: []string{"sudo"}}
	}

	check(t, "admin sudo", JudgeEV03(base(source.Elevation{From: "ana", To: "root", Method: "sudo"})), want{verdict.Compliant, "", []string{"1 elevations"}})
	check(t, "su to root by eva", JudgeEV03(base(source.Elevation{From: "eva", To: "root", Method: "su"})), want{verdict.NonCompliant, "", []string{"su by eva to root"}})
	check(t, "lateral", JudgeEV03(base(source.Elevation{From: "eva", To: "ops1", Method: "su"})), want{verdict.Compliant, "", nil})
	check(t, "refusal", JudgeEV03(base(source.Elevation{From: "eva", To: "root", Method: "sudo", Denied: true})), want{verdict.Compliant, "", []string{"1 refused"}})
	check(t, "LDAP user", JudgeEV03(base(source.Elevation{From: "ldapuser", To: "root", Method: "sudo"})), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"not a local account"}})

	blind := base(source.Elevation{From: "eva", To: "root", Method: "sudo"})
	blind.Sudoers = sudoers(1, grant("group", "sudo"))
	check(t, "sudoers blind spots", JudgeEV03(blind), want{verdict.NotEvaluable, verdict.CauseCollection, nil})

	quiet := base()
	quiet.Log = passes.AuthLog{Known: true, Detail: "probes never reached Wazuh"}
	check(t, "quiet and blind", JudgeEV03(quiet), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"never reached"}})
	check(t, "quiet and reaching", JudgeEV03(base()), want{verdict.Compliant, "", nil})
}

func TestJudgeEV04(t *testing.T) {

	acls := func(records ...fact.ACLRecord) ACLs {
		return ACLs{Snapshot: &fact.ACLSnapshot{Config: "/var/ossec/etc/shared/oscompliance.json", Status: fact.SourceRead, RecordsEmitted: len(records)}, Records: records}
	}
	datos := fact.ACLRecord{Path: "/srv/datos", Status: fact.SourceRead, Mode: "0750", Owner: "root:ops", ACL: []string{"g:auditors:r-x", "m::r-x", "u:auditor:r-x"}}

	check(t, "as declared", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:ops | user:auditor:rx, g:auditors:r-x"}}), want{verdict.Compliant, "", []string{"1 resources"}})
	check(t, "mode", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 0700 | | u:auditor:r-x,g:auditors:r-x"}}), want{verdict.NonCompliant, "", []string{"mode 0750, declared 0700"}})
	check(t, "owner", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:root | u:auditor:r-x g:auditors:r-x"}}), want{verdict.NonCompliant, "", []string{"owner root:ops"}})
	check(t, "undeclared entry", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | root:ops | u:auditor:r-x"}}), want{verdict.NonCompliant, "", []string{"undeclared g:auditors:r-x"}})
	check(t, "missing entry", JudgeEV04(EV04Input{ACLs: acls(datos), Rows: []string{"/srv/datos | 750 | | u:auditor:r-x g:auditors:r-x u:eva:rwx"}}), want{verdict.NonCompliant, "", []string{"lacks u:eva:rwx"}})
	check(t, "path missing", JudgeEV04(EV04Input{ACLs: acls(fact.ACLRecord{Path: "/srv/x", Status: fact.SourceAbsent}), Rows: []string{"/srv/x | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"does not exist"}})
	check(t, "not sent", JudgeEV04(EV04Input{ACLs: acls(), Rows: []string{"/srv/y | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"not in the paths"}})
	check(t, "no shared file", JudgeEV04(EV04Input{ACLs: ACLs{Snapshot: &fact.ACLSnapshot{Status: fact.SourceAbsent}}, Rows: []string{"/srv/y | 750 | |"}}), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"oscompliance.json"}})
	check(t, "P-08 missing", JudgeEV04(EV04Input{RowsProblem: "not set"}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}

func TestJudgeEV06(t *testing.T) {

	watches := &fact.AuditWatchSnapshot{Auditd: fact.AuditdRunning, Wanted: []string{"/srv/datos"}, Loaded: []string{"/srv/datos"}}
	config := &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Location: "/var/log/audit/audit.log", Format: "audit"}}}
	rules := []string{"ops | /srv/datos | lectura,escritura", "ops | /srv/datos/ro | lectura"}
	profiles := []string{"ana | ops | sudo:no"}
	access := func(key, auid, path string) source.AuditAccess {
		return source.AuditAccess{Key: key, Success: "yes", AUID: auid, Path: path}
	}
	base := func(a ...source.AuditAccess) EV06Input {
		return EV06Input{Watches: watches, Config: config, Accesses: a, Accounts: accounts(), Rules: rules, Profiles: profiles}
	}

	check(t, "within", JudgeEV06(base(access("oscompliance_write", "1000", "/srv/datos/a.txt"))), want{verdict.Compliant, "", []string{"1 accesses"}})
	check(t, "longest path wins", JudgeEV06(base(access("oscompliance_write", "1000", "/srv/datos/ro/b.txt"))), want{verdict.NonCompliant, "", []string{"escritura by ana (profile ops) on /srv/datos/ro/b.txt"}})
	check(t, "no profile", JudgeEV06(base(access("oscompliance_exec", "1002", "/srv/datos/x"))), want{verdict.Compliant, "", []string{"1 by accounts without a P-09 profile"}})
	check(t, "no person", JudgeEV06(base(access("oscompliance_read", "4294967295", "/srv/datos/x"))), want{verdict.NotEvaluable, verdict.CauseEvidence, []string{"no person"}})

	stopped := base()
	stopped.Watches = &fact.AuditWatchSnapshot{Auditd: fact.AuditdAbsent}
	check(t, "no auditd", JudgeEV06(stopped), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"auditd absent"}})
	unread := base()
	unread.Config = &fact.WazuhAgentConfig{Status: fact.SourceRead}
	check(t, "audit log not read", JudgeEV06(unread), want{verdict.NotEvaluable, verdict.CauseCollection, []string{"log_format audit"}})
	check(t, "params", JudgeEV06(EV06Input{Problem: "P-06: not set"}), want{verdict.NotEvaluable, verdict.CauseConfiguration, nil})
}

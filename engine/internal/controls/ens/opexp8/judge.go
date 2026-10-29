// Package opexp8 judges op.exp.8, activity logging: the audit log and its delivery, the clock, the
// indexer's retention and backups, who reads the logs, and the manager's analysis and response.
package opexp8

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

var systemLogs = []string{"journald", "/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure"}

func JudgeEV01(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig) verdict.Judgement {

	switch {
	case w == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.AuditWatchSnapshotFact))
	case c == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	}

	var missing []catalog.Message
	if w.Auditd != fact.AuditdRunning {
		missing = append(missing, catalog.Says("opexp8.auditd", "state", w.Auditd))
	}
	if !slices.ContainsFunc(c.Localfiles, func(l fact.AgentLocalfile) bool { return l.Format == "audit" }) {
		missing = append(missing, catalog.Says("chain.no_audit_log"))
	}
	if !slices.ContainsFunc(c.Localfiles, func(l fact.AgentLocalfile) bool { return slices.Contains(systemLogs, l.Location) }) {
		missing = append(missing, catalog.Says("opexp8.no_system_log"))
	}

	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.log_incomplete", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.log_complete", "rules", len(w.Loaded)))
}

func JudgeEV03(total int, fields map[string]int) verdict.Judgement {

	if total == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp8.no_audit_records"))
	}
	var short []string
	for _, f := range []string{"usuario", "objeto", "tipo", "resultado"} {
		if fields[f] < total {
			short = append(short, fmt.Sprintf("%s %d/%d", f, fields[f], total))
		}
	}
	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.fields_missing", "list", short))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.fields_complete", "count", total))
}

// JudgeEV04 fails a record of the window with the agent not active, or a silence longer than maxHours.
func JudgeEV04(records []source.MonitoringRecord, manager bool, maxHours int, problem catalog.Message, from, now time.Time) verdict.Judgement {

	if manager {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.manager_reporting"))
	}
	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if len(records) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.never_reported"))
	}

	limit := time.Duration(maxHours) * time.Hour
	var gaps []string
	last := from
	for _, r := range records {
		if r.Time.Sub(last) > limit {
			gaps = append(gaps, last.Format("2006-01-02 15:04")+" → "+r.Time.Format("15:04"))
		}
		if r.Status != "active" {
			gaps = append(gaps, r.Time.Format("2006-01-02 15:04")+" "+r.Status)
		}
		last = r.Time
	}
	if now.Sub(last) > limit {
		gaps = append(gaps, last.Format("2006-01-02 15:04")+" →")
	}
	gaps = slices.Compact(gaps)

	if len(gaps) > 0 {
		if len(gaps) > 10 {
			gaps = append(gaps[:10], "…")
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.gaps", "list", gaps, "max", maxHours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.continuous", "count", len(records), "max", maxHours))
}

func JudgeEV06(t *fact.TimeSync, sources []string, maxOffset float64, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case t == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.TimeSyncFact))
	case t.Tool == "none":
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.no_time_sync"))
	}

	var why []catalog.Message
	if !t.Synchronised {
		why = append(why, catalog.Says("opexp8.not_synchronised"))
	}
	if t.Tool == "chrony" && math.Abs(t.Offset) > maxOffset {
		why = append(why, catalog.Says("opexp8.offset", "offset", t.Offset, "max", maxOffset))
	}
	var declared []string
	auth := false
	for _, r := range sources {
		src, method, _ := strings.Cut(r, "|")
		declared = append(declared, strings.TrimSpace(src))
		if m := strings.ToLower(strings.TrimSpace(method)); m == "nts" || m == "clave" || m == "key" {
			auth = true
		}
	}
	if len(declared) > 0 && !slices.ContainsFunc(t.Sources, func(s string) bool { return slices.Contains(declared, s) }) {
		why = append(why, catalog.Says("opexp8.sources", "sources", t.Sources))
	}
	if auth && !t.Authenticated {
		why = append(why, catalog.Says("opexp8.unauthenticated"))
	}

	if len(why) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.time_wrong", "list", why))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.time_right", "tool", t.Tool, "sources", t.Sources))
}

// LongestRetention is the most days P-07 asks to keep any category.
func LongestRetention(rows []string) int {
	longest := 0
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) < 2 {
			continue
		}
		if d, err := strconv.Atoi(strings.TrimSpace(c[1])); err == nil && d > longest {
			longest = d
		}
	}
	return longest
}

func JudgeEV07(deletesAfter int, managed bool, wanted int, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case wanted == 0:
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_set", "param", "P-07"))
	case !managed:
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.kept_forever", "wanted", wanted))
	case deletesAfter < wanted:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.deleted_early", "days", deletesAfter, "wanted", wanted))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.retention", "days", deletesAfter, "wanted", wanted))
}

// JudgeEV08 fails a log path readable by everyone, or an ACL naming an account outside P-08.
func JudgeEV08(s *fact.ACLSnapshot, records []fact.ACLRecord, paths []string, accounts []string, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case len(paths) == 0:
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_set", "param", "P-14"))
	case s == nil || s.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ACLSnapshotFact))
	}

	by := map[string]fact.ACLRecord{}
	for _, r := range records {
		by[r.Path] = r
	}
	var open []string
	checked := 0
	for _, p := range paths {
		r, ok := by[p]
		switch {
		case !ok:
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.acl_not_sent", "path", p))
		case r.Status == fact.SourceAbsent:
			continue
		case r.Status != fact.SourceRead:
			return passes.Gap(verdict.CauseCollection, catalog.Says("item.error", "path", p, "error", r.Error))
		}
		checked++
		if mode, err := strconv.ParseUint(r.Mode, 8, 32); err == nil && mode&0o004 != 0 {
			open = append(open, p+" (todos)")
		}
		for _, entry := range r.ACL {
			f := strings.Split(entry, ":")
			if len(f) >= 3 && f[0] == "user" && f[1] != "" && strings.Contains(f[2], "r") && !slices.Contains(accounts, f[1]) {
				open = append(open, p+" ("+f[1]+")")
			}
		}
	}

	if len(open) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.logs_open", "list", open))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.logs_closed", "count", checked))
}

// ShortestFrequency is the fewest days between backups P-09 declares: a number, or diaria, semanal, mensual.
func ShortestFrequency(rows []string) int {
	words := map[string]int{"diaria": 1, "semanal": 7, "mensual": 31}
	shortest := 0
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) < 3 {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(c[2]))
		d, err := strconv.Atoi(v)
		if err != nil {
			d = words[v]
		}
		if d > 0 && (shortest == 0 || d < shortest) {
			shortest = d
		}
	}
	return shortest
}

func JudgeEV09(newest time.Time, days int, problem catalog.Message, now time.Time) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case days == 0:
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_set", "param", "P-09"))
	case newest.IsZero():
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.no_snapshot"))
	case now.Sub(newest) > time.Duration(days)*24*time.Hour:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.snapshot_old", "date", newest.Format("2006-01-02 15:04"), "days", days))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.snapshot", "date", newest.Format("2006-01-02 15:04"), "days", days))
}

func JudgeEV10(manager *fact.WazuhAgentConfig, sets []string, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case manager == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.manager_config_unknown"))
	}
	custom := slices.DeleteFunc(slices.Clone(manager.CustomRules), func(f string) bool { return f == "local_rules.xml" })

	var missing []string
	for _, s := range sets {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "wazuh":
			if manager.RulesetFiles == 0 {
				missing = append(missing, "wazuh")
			}
		case "propias":
			if len(custom) == 0 {
				missing = append(missing, "propias")
			}
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.rules_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.rules", "ruleset", manager.RulesetFiles, "custom", custom))
}

func JudgeEV11(actions []string, c *fact.WazuhAgentConfig, p *fact.MalwareProtection, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case c == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	case p == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.MalwareProtectionFact))
	}
	var missing []string
	for _, a := range actions {
		if a = strings.TrimSpace(a); a != "" && (!slices.Contains(c.ActiveResponses, a) || !slices.Contains(p.Responses, a)) {
			missing = append(missing, a)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.responses_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.responses", "list", actions))
}

func JudgeEV12(times []time.Time, from time.Time) verdict.Judgement {
	n := 0
	for _, t := range times {
		if !t.Before(from) {
			n++
		}
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.responses_run", "count", n))
}

func JudgeEV13(reporting verdict.Judgement, c *fact.WazuhAgentConfig) verdict.Judgement {

	if reporting.Status != verdict.Compliant {
		return reporting
	}
	if c == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	}
	watched := !c.SyscheckDisabled && slices.ContainsFunc(c.Directories, func(d fact.FIMDirectory) bool {
		return d.Path == "/var/ossec/etc" || d.Path == "/var/ossec" || strings.HasPrefix("/var/ossec/etc", strings.TrimRight(d.Path, "/")+"/")
	})
	if !watched {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp8.agent_unwatched"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp8.agent_watched"))
}

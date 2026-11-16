package opexp7

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Class struct {
	Category, Severity string
	Level              int
	Notifiable         bool
}

func ParseClasses(rows []string) ([]Class, catalog.Message) {
	var out []Class
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 4 {
			c = append(c, "")
		}
		level, err := strconv.Atoi(strings.TrimSpace(c[2]))
		if err != nil || level < 0 || level > 16 {
			return nil, catalog.Says("opexp7.level_invalid", "value", strings.TrimSpace(c[2]))
		}
		notifiable := strings.EqualFold(strings.TrimSpace(c[3]), "si") || strings.EqualFold(strings.TrimSpace(c[3]), "sí")
		out = append(out, Class{Category: strings.TrimSpace(c[0]), Severity: Severity(c[1]), Level: level, Notifiable: notifiable})
	}
	if len(out) == 0 {
		return nil, catalog.Says("param.not_set", "param", "P-01")
	}
	return out, catalog.Message{}
}

func SeverityOf(classes []Class, level int) string {
	best, sev := -1, ""
	for _, c := range classes {
		if level >= c.Level && c.Level > best {
			best, sev = c.Level, c.Severity
		}
	}
	return sev
}

func MinLevel(classes []Class) int {
	m := 16
	for _, c := range classes {
		m = min(m, c.Level)
	}
	return m
}

func bySeverity(rows []string) map[string][]string {
	out := map[string][]string{}
	for _, r := range rows {
		c := strings.Split(r, "|")
		for i := range c {
			c[i] = strings.TrimSpace(c[i])
		}
		if len(c) > 0 && c[0] != "" {
			out[Severity(c[0])] = c
		}
	}
	return out
}

func hours(cells []string, i int) (int, bool) {
	if i >= len(cells) {
		return 0, false
	}
	n, err := strconv.Atoi(cells[i])
	return n, err == nil && n >= 0
}

func JudgeEV01(hoursWithAlerts []source.AlertHour, classes []Class, reporting bool, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	counts := map[string]int{}
	for _, h := range hoursWithAlerts {
		counts[SeverityOf(classes, h.Level)]++
	}
	var list []string
	for _, c := range classes {
		if n := counts[c.Severity]; n > 0 && !slices.ContainsFunc(list, func(s string) bool { return strings.HasPrefix(s, c.Severity+" ") }) {
			list = append(list, fmt.Sprintf("%s %d h", c.Severity, n))
		}
	}
	if len(list) == 0 && !reporting {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp7.not_reporting"))
	}
	if len(list) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.no_relevant_alerts", "level", MinLevel(classes)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.detection", "list", list, "level", MinLevel(classes)))
}

func JudgeEV02(hoursWithAlerts []source.AlertHour, classes []Class, escalation []string, incidents []Incident, machine string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	deadlines := bySeverity(escalation)

	var orphans []string
	for _, h := range hoursWithAlerts {
		sev := SeverityOf(classes, h.Level)
		limit, ok := hours(deadlines[sev], 2)
		if !ok {
			limit = 24
		}
		opened := slices.ContainsFunc(incidents, func(in Incident) bool {
			o := in.Opened()
			return in.Involves(machine) && !o.Before(h.Hour.Add(-time.Hour)) && !o.After(h.Hour.Add(time.Duration(limit+1)*time.Hour))
		})
		if !opened {
			orphans = append(orphans, fmt.Sprintf("%s (%s, nivel %d)", h.Hour.UTC().Format("2006-01-02 15:00"), sev, h.Level))
		}
	}

	if len(orphans) > 0 {
		total := len(orphans)
		if len(orphans) > 10 {
			orphans = append(orphans[:10], "…")
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.orphan_alerts", "count", total, "list", orphans))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.alerts_reconciled", "count", len(hoursWithAlerts)))
}

func JudgeEV03(incidents []Incident, deadlines []string, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	rows := bySeverity(deadlines)

	var late []string
	for _, in := range incidents {
		r := rows[in.Severity()]
		opened := in.Opened()
		if contain, ok := hours(r, 1); ok {
			mid, has := in.phase("intermedio")
			reached := mid.Date
			if !has {
				reached = in.Closed()
			}
			if (reached.IsZero() && now.Sub(opened) > time.Duration(contain)*time.Hour) || (!reached.IsZero() && reached.Sub(opened) > time.Duration(contain)*time.Hour) {
				late = append(late, in.ID+" (contención)")
			}
		}
		if resolve, ok := hours(r, 2); ok && in.End(now).Sub(opened) > time.Duration(resolve)*time.Hour {
			late = append(late, in.ID+" (resolución)")
		}
	}

	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.late", "list", late))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.in_time", "count", len(incidents)))
}

func JudgeEV04(incidents []Incident, escalation, owners []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	recipients := bySeverity(escalation)
	bySystem := bySeverity(owners)

	var wrong []string
	for _, in := range incidents {
		if r := recipients[in.Severity()]; len(r) > 1 && r[1] != "" && !strings.Contains(strings.ToLower(in.Field(func(p Phase) string { return p.Escalated })), strings.ToLower(r[1])) {
			wrong = append(wrong, in.ID+" (escalado a "+r[1]+")")
		}
		notified := strings.ToLower(in.Field(func(p Phase) string { return p.Notified }))
		for _, s := range in.Systems() {
			o := bySystem[strings.ToLower(s)]
			for _, who := range o[min(1, len(o)):] {
				if who != "" && !strings.Contains(notified, strings.ToLower(who)) {
					wrong = append(wrong, in.ID+" ("+who+")")
				}
			}
		}
	}
	slices.Sort(wrong)

	if len(wrong) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.not_escalated", "list", slices.Compact(wrong)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.escalated", "count", len(incidents)))
}

func days(in Incident, now time.Time) []string {
	var out []string
	for d := in.Opened().UTC().Truncate(24 * time.Hour); !d.After(in.End(now)); d = d.AddDate(0, 0, 1) {
		out = append(out, d.Format("2006-01-02"))
	}
	return out
}

func JudgeEV05(incidents []Incident, manager *fact.WazuhAgentConfig, now time.Time) verdict.Judgement {

	if manager == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.manager_config_unknown"))
	}
	today := now.UTC().Format("2006-01-02")
	var unsealed []string
	for _, in := range incidents {
		for _, d := range days(in, now) {
			if d != today && !slices.Contains(manager.SealedDays, d) {
				unsealed = append(unsealed, in.ID+" "+d)
			}
		}
	}
	if len(unsealed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.unsealed", "list", unsealed))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.sealed", "count", len(incidents)))
}

func Responded(in Incident, responses []time.Time, now time.Time) bool {
	return slices.ContainsFunc(responses, func(t time.Time) bool { return !t.Before(in.Opened().Truncate(time.Hour)) && !t.After(in.End(now)) })
}

func serious(s string) bool { return s == "alta" || s == "critica" }

func JudgeEV06(incidents []Incident, responses []time.Time, now time.Time) verdict.Judgement {

	var bare []string
	checked := 0
	for _, in := range incidents {
		if !serious(in.Severity()) {
			continue
		}
		checked++
		if !Responded(in, responses, now) && !in.Has("intermedio") {
			bare = append(bare, in.ID)
		}
	}
	if len(bare) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.no_containment", "list", bare))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.contained", "count", checked))
}

func JudgeEV07(incidents []Incident, personal []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	systems := bySeverity(personal)
	var wrong []string
	checked := 0
	for _, in := range incidents {
		affected := slices.ContainsFunc(in.Systems(), func(s string) bool { _, ok := systems[strings.ToLower(s)]; _, all := systems["*"]; return ok || all })
		if !affected {
			continue
		}
		checked++
		value := in.Field(func(p Phase) string { return p.Personal })
		switch {
		case value == "":
			wrong = append(wrong, in.ID+" (sin valorar)")
		case value == "si" || value == "sí":
			if !in.Any(func(p Phase) bool { return !empty(p.Notified) && p.Date.Sub(in.Opened()) <= 72*time.Hour }) {
				wrong = append(wrong, in.ID+" (72 h)")
			}
		}
	}
	if len(wrong) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.personal_data", "list", wrong))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.personal_data_ok", "count", checked))
}

func JudgeEV08(incidents []Incident, classes []Class, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	var missing []string
	checked := 0
	for _, in := range incidents {
		class := in.Field(func(p Phase) string { return p.Class })
		notifiable := slices.ContainsFunc(classes, func(c Class) bool {
			return c.Notifiable && (strings.EqualFold(c.Category, class) || (c.Category == "" && c.Severity == in.Severity()))
		})
		if !notifiable {
			continue
		}
		checked++
		if in.Field(func(p Phase) string { return p.CCNCERT }) == "" {
			missing = append(missing, in.ID)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.ccn_cert_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.ccn_cert", "count", checked))
}

func JudgeEV09(incidents []Incident, responses []time.Time, now time.Time) verdict.Judgement {

	var bare []string
	checked := 0
	for _, in := range incidents {
		if in.Severity() != "critica" {
			continue
		}
		checked++
		if !Responded(in, responses, now) {
			bare = append(bare, in.ID)
		}
	}
	if len(bare) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.no_reconfiguration", "list", bare))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.reconfigured", "count", checked))
}

func JudgeEV10(manager *fact.WazuhAgentConfig, rows []string, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if manager == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.manager_config_unknown"))
	}
	if len(rows) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_set", "param", "P-11"))
	}
	c := strings.Split(rows[0], "|")
	for len(c) < 4 {
		c = append(c, "")
	}
	list, limit := strings.TrimSpace(c[2]), strings.TrimSpace(c[3])
	maxDays, err := strconv.Atoi(limit)
	if err != nil || maxDays < 1 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_days", "param", "P-11", "value", limit))
	}
	for _, l := range manager.Lists {
		if l.Name != list {
			continue
		}
		modified, err := time.Parse(time.RFC3339, l.Modified)
		if err == nil && now.Sub(modified) <= time.Duration(maxDays)*24*time.Hour {
			return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.list_current", "list", list, "date", modified.UTC().Format("2006-01-02")))
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.list_old", "list", list, "date", l.Modified, "max", maxDays))
	}
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.list_missing", "list", list))
}

func JudgeEV12(incidents []Incident) verdict.Judgement {
	var missing []string
	checked := 0
	for _, in := range incidents {
		if in.Closed().IsZero() {
			continue
		}
		checked++
		if in.Field(func(p Phase) string { return p.Lessons }) == "" {
			missing = append(missing, in.ID)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp7.no_lessons", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp7.lessons", "count", checked))
}

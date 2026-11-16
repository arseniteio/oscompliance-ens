package opmon1

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

var Daemons = []string{"wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd"}

var NetworkGroups = []string{"ids", "suricata", "snort", "zeek", "nids"}

type Range struct{ From, To int }

func ParseRules(s string) ([]Range, error) {
	var out []Range
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		from, to, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(from)
		if err != nil {
			return nil, fmt.Errorf("%q is not a rule id", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(to); err != nil || b < a {
				return nil, fmt.Errorf("%q is not a range of rule ids", part)
			}
		}
		out = append(out, Range{a, b})
	}
	return out, nil
}

func Alerting(rules []source.Rule, ranges []Range) []source.Rule {
	var out []source.Rule
	for _, r := range rules {
		if r.Level > 0 && slices.ContainsFunc(ranges, func(g Range) bool { return r.ID >= g.From && r.ID <= g.To }) {
			out = append(out, r)
		}
	}
	return out
}

func InSet(r source.Rule, set string) bool {
	switch strings.ToLower(set) {
	case "wazuh":
		return !r.Custom()
	case "propias":
		return r.Custom()
	}
	return r.File == set
}

func JudgeEV01(m *source.Manager, sets []string) verdict.Judgement {

	var stopped []string
	for _, d := range Daemons {
		if m.Daemons[d] != "running" {
			stopped = append(stopped, d+" "+m.Daemons[d])
		}
	}
	if len(stopped) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.daemons_stopped", "list", stopped))
	}

	alerting := 0
	for _, r := range m.Rules {
		if r.Level > 0 {
			alerting++
		}
	}
	if alerting == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.no_rules"))
	}

	var short []catalog.Message
	for _, row := range sets {
		c := passes.Cells(row, 3)
		want, _ := strconv.Atoi(c[2])
		got := 0
		for _, r := range m.Rules {
			if r.Level > 0 && InSet(r, c[0]) {
				got++
			}
		}
		if got == 0 || got < want {
			short = append(short, catalog.Says("opmon1.item_set", "name", c[0], "got", got, "want", want))
		}
	}
	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.sets_short", "list", short))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.detecting", "rules", alerting, "sets", len(sets)))
}

func JudgeEV02(reporting *source.Reporting, config *fact.WazuhAgentConfig, maxHours int, now time.Time) verdict.Judgement {

	switch {
	case reporting == nil || reporting.LastKeepAlive.IsZero():
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.not_reporting"))
	case now.Sub(reporting.LastKeepAlive) > time.Duration(maxHours)*time.Hour:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.silent", "date", day(reporting.LastKeepAlive), "max", maxHours))
	case config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	case config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", config.Status, config.Error))
	}

	var off []string
	if config.SyscheckDisabled {
		off = append(off, "syscheck")
	}
	if config.SCADisabled {
		off = append(off, "sca")
	}
	if len(off) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.analysis_off", "list", off))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.covered", "date", day(reporting.LastKeepAlive)))
}

func JudgeEV03(d source.Detection, maxDays int, now time.Time) verdict.Judgement {
	if d.Last.IsZero() || now.Sub(d.Last) > time.Duration(maxDays)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.no_detections", "days", maxDays))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.detections", "count", d.Count, "date", day(d.Last)))
}

func JudgeEV04(m *source.Manager, rows []string) verdict.Judgement {

	var blind, covered []catalog.Message
	for _, row := range rows {
		c := passes.Cells(row, 3)
		ranges, err := ParseRules(c[2])
		if err != nil || len(ranges) == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon1.bad_rules", "name", c[0], "rules", c[2]))
		}
		n := len(Alerting(m.Rules, ranges))
		if n == 0 {
			blind = append(blind, catalog.Says("item.name_detail", "name", c[0], "detail", c[2]))
		} else {
			covered = append(covered, catalog.Says("opmon1.item_rules", "name", c[0], "count", n))
		}
	}
	if len(blind) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.situations_blind", "list", blind))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.situations_covered", "list", covered))
}

func JudgeEV05(row string, network source.Detection, maxDays int, now time.Time) verdict.Judgement {
	c := passes.Cells(row, 3)
	if strings.ToLower(c[0]) != "si" && strings.ToLower(c[0]) != "sí" {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.network_not_needed", "why", c[2]))
	}
	if network.Last.IsZero() || now.Sub(network.Last) > time.Duration(maxDays)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.network_silent", "product", c[1], "days", maxDays))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.network_alerts", "product", c[1], "count", network.Count, "date", day(network.Last)))
}

func JudgeEV07(m *source.Manager, rows []string, runs int) verdict.Judgement {

	var missing []string
	for _, row := range rows {
		action := passes.Cells(row, 1)[0]
		if !slices.ContainsFunc(m.Responses, func(r source.Response) bool { return r.Command == action && !r.Disabled }) {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.responses_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.responses", "count", len(rows), "runs", runs))
}

func Silenced(m *source.Manager) []string {
	out := slices.Clone(m.RuleExclude)
	for _, r := range m.Rules {
		if r.Custom() && r.Level == 0 && r.ID < 100000 {
			out = append(out, strconv.Itoa(r.ID))
		}
	}
	return out
}

func JudgeEV08(m *source.Manager, approved []string, maxDays int, now time.Time) verdict.Judgement {

	if m.Installed.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opmon1.ruleset_undated"))
	}
	age := int(now.Sub(m.Installed).Hours() / 24)
	if age > maxDays {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.ruleset_old", "version", m.Version, "days", age, "max", maxDays))
	}

	known := map[string]bool{}
	for _, row := range approved {
		c := passes.Cells(row, 3)
		if c[0] != "" && c[1] != "" && c[2] != "" {
			known[c[0]] = true
		}
	}
	var unapproved []string
	for _, s := range Silenced(m) {
		if !known[s] {
			unapproved = append(unapproved, s)
		}
	}
	if len(unapproved) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.silenced_unapproved", "list", unapproved))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.ruleset_current", "version", m.Version, "days", age, "silenced", len(Silenced(m))))
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

func ReportingOf(agentID string, all map[string]source.Reporting, m *source.Manager, now time.Time) *source.Reporting {
	if r, ok := all[agentID]; ok {
		return &r
	}
	if agentID == source.ManagerID && m != nil && m.Daemons["wazuh-analysisd"] == "running" {
		return &source.Reporting{Status: "active", LastKeepAlive: now}
	}
	return nil
}

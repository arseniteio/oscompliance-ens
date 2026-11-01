// Package opmon1 judges op.mon.1, intrusion detection, over the Wazuh manager's own state and the alerts
// of each machine.
package opmon1

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Daemons are the manager processes without which nothing is detected.
var Daemons = []string{"wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd"}

// NetworkGroups are the rule groups of network intrusion detection Wazuh decodes.
var NetworkGroups = []string{"ids", "suricata", "snort", "zeek", "nids"}

// Range is an inclusive span of rule ids.
type Range struct{ From, To int }

func (r Range) String() string {
	if r.From == r.To {
		return strconv.Itoa(r.From)
	}
	return fmt.Sprintf("%d-%d", r.From, r.To)
}

// ParseRules reads rule ids and ranges such as `5710, 5712, 80700-80799`.
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

// Alerting are the loaded rules that can raise an alert: level 1 or more.
func Alerting(rules []source.Rule, ranges []Range) []source.Rule {
	var out []source.Rule
	for _, r := range rules {
		if r.Level > 0 && slices.ContainsFunc(ranges, func(g Range) bool { return r.ID >= g.From && r.ID <= g.To }) {
			out = append(out, r)
		}
	}
	return out
}

// InSet tells whether a rule belongs to a rule set of P-02: `wazuh` for the shipped ruleset, `propias`
// for etc/rules, or the name of a rule file.
func InSet(r source.Rule, set string) bool {
	switch strings.ToLower(set) {
	case "wazuh":
		return !r.Custom()
	case "propias":
		return r.Custom()
	}
	return r.File == set
}

func cells(row string, n int) []string {
	c := strings.Split(row, "|")
	for len(c) < n {
		c = append(c, "")
	}
	for i := range c {
		c[i] = strings.TrimSpace(c[i])
	}
	return c
}

// JudgeEV01 needs the manager's detection processes running and rules loaded, each rule set of P-02
// (`conjunto | descripcion | minimo_reglas`) with at least its rules.
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
		c := cells(row, 3)
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

// JudgeEV02 needs the machine reporting to the manager within maxHours and its FIM and SCA enabled.
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

// JudgeEV03 needs an alert of the machine, OSCompliance's own facts left out, within maxDays.
func JudgeEV03(d source.Detection, maxDays int, now time.Time) verdict.Judgement {
	if d.Last.IsZero() || now.Sub(d.Last) > time.Duration(maxDays)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.no_detections", "days", maxDays))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.detections", "count", d.Count, "date", day(d.Last)))
}

// JudgeEV04 needs every compromise situation of P-03 (`situacion | ambito | reglas`) covered by a loaded
// rule that can alert.
func JudgeEV04(m *source.Manager, rows []string) verdict.Judgement {

	var blind, covered []catalog.Message
	for _, row := range rows {
		c := cells(row, 3)
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

// JudgeEV05 needs, when P-01 (`necesaria | producto | justificacion`) says the risk analysis asks for
// network detection, network intrusion alerts within maxDays.
func JudgeEV05(row string, network source.Detection, maxDays int, now time.Time) verdict.Judgement {
	c := cells(row, 3)
	if strings.ToLower(c[0]) != "si" && strings.ToLower(c[0]) != "sí" {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.network_not_needed", "why", c[2]))
	}
	if network.Last.IsZero() || now.Sub(network.Last) > time.Duration(maxDays)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.network_silent", "product", c[1], "days", maxDays))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.network_alerts", "product", c[1], "count", network.Count, "date", day(network.Last)))
}

// JudgeEV07 needs every automatic action of P-06 (`accion | reglas | alcance | timeout`) configured and
// enabled in the manager.
func JudgeEV07(m *source.Manager, rows []string, runs int) verdict.Judgement {

	var missing []string
	for _, row := range rows {
		action := cells(row, 1)[0]
		if !slices.ContainsFunc(m.Responses, func(r source.Response) bool { return r.Command == action && !r.Disabled }) {
			missing = append(missing, action)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.responses_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.responses", "count", len(rows), "runs", runs))
}

// Silenced are the rule files the manager excludes and the stock rules it rewrites to level 0.
func Silenced(m *source.Manager) []string {
	out := slices.Clone(m.RuleExclude)
	for _, r := range m.Rules {
		if r.Custom() && r.Level == 0 && r.ID < 100000 {
			out = append(out, strconv.Itoa(r.ID))
		}
	}
	return out
}

// JudgeEV08 needs the ruleset installed within maxDays and every silenced rule or file in P-05
// (`regla | motivo | aprobador`).
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
		c := cells(row, 3)
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

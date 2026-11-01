// Package opmon3 judges op.mon.3, security monitoring, over the Wazuh manager's state, the logs each machine
// sends and the inspections the organisation records.
package opmon3

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Collectors are the manager processes that receive and store events.
var Collectors = []string{"wazuh-remoted", "wazuh-analysisd", "wazuh-db"}

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

// JudgeEV01 needs the manager receiving events and the machine sending them within maxHours.
func JudgeEV01(m *source.Manager, reporting *source.Reporting, maxHours int, now time.Time) verdict.Judgement {

	var stopped []string
	for _, d := range Collectors {
		if m.Daemons[d] != "running" {
			stopped = append(stopped, d+" "+m.Daemons[d])
		}
	}
	switch {
	case len(stopped) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.daemons_stopped", "list", stopped))
	case reporting == nil || reporting.LastKeepAlive.IsZero():
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.not_reporting"))
	case now.Sub(reporting.LastKeepAlive) > time.Duration(maxHours)*time.Hour:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.silent", "date", day(reporting.LastKeepAlive), "max", maxHours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.collecting", "date", day(reporting.LastKeepAlive)))
}

// Sources are the rows of P-01 (`fuente | sistema | ubicacion | max_horas`) of a machine: its name or `*`.
func Sources(rows []string, machine string) [][]string {
	var out [][]string
	for _, r := range rows {
		c := cells(r, 4)
		if c[1] == "*" || strings.EqualFold(c[1], machine) {
			out = append(out, c)
		}
	}
	return out
}

// JudgeEV02 needs every source of the machine read by its agent and sending events within its hours.
func JudgeEV02(sources [][]string, config *fact.WazuhAgentConfig, seen map[string]time.Time, now time.Time) verdict.Judgement {

	if len(sources) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon3.no_sources"))
	}
	switch {
	case config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	case config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", config.Status, config.Error))
	}

	var failing, flowing []catalog.Message
	for _, c := range sources {
		name, location := c[0], c[2]
		hours, _ := strconv.Atoi(c[3])
		if hours == 0 {
			hours = 24
		}
		read := slices.ContainsFunc(config.Localfiles, func(l fact.AgentLocalfile) bool { return l.Location == location })
		last := seen[location]
		switch {
		case !read:
			failing = append(failing, catalog.Says("opmon3.item_unread", "name", name, "location", location))
		case last.IsZero() || now.Sub(last) > time.Duration(hours)*time.Hour:
			failing = append(failing, catalog.Says("opmon3.item_silent", "name", name, "location", location, "hours", hours))
		default:
			flowing = append(flowing, catalog.Says("mpinfo6.item_date", "name", name, "date", day(last)))
		}
	}
	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.sources_failing", "list", failing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.sources_flowing", "list", flowing))
}

// JudgeEV03 needs correlation rules loaded, each rule set of P-02 (`conjunto | minimo_reglas_correlacion`)
// with at least its own.
func JudgeEV03(m *source.Manager, sets []string) verdict.Judgement {

	total := 0
	for _, r := range m.Rules {
		if r.Correlates && r.Level > 0 {
			total++
		}
	}
	if total == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.no_correlation"))
	}

	var short []catalog.Message
	for _, row := range sets {
		c := cells(row, 2)
		want, _ := strconv.Atoi(c[1])
		got := 0
		for _, r := range m.Rules {
			if r.Correlates && r.Level > 0 && opmon1.InSet(r, c[0]) {
				got++
			}
		}
		if got == 0 || got < want {
			short = append(short, catalog.Says("opmon1.item_set", "name", c[0], "got", got, "want", want))
		}
	}
	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.correlation_short", "list", short))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.correlating", "count", total))
}

// Surface is what Wazuh knows of the machine's exposure: its SCA enabled with a result, and its packages
// inventoried for the vulnerability detector.
type Surface struct {
	SCAEnabled bool
	SCAResults int
	Packages   int
	Detector   bool
}

// JudgeEV04 needs the vulnerability detector enabled over the machine's packages and SCA results of it.
func JudgeEV04(s Surface) verdict.Judgement {
	var missing []string
	if !s.Detector {
		missing = append(missing, "vulnerability-detection")
	}
	if s.Packages == 0 {
		missing = append(missing, "syscollector")
	}
	if !s.SCAEnabled || s.SCAResults == 0 {
		missing = append(missing, "sca")
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.surface_blind", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.surface", "packages", s.Packages, "policies", s.SCAResults))
}

// JudgeEV06 needs a network probe in P-05 (`producto | ubicacion | dias_maximos_sin_alerta`) whose alerts
// reach the manager within its days.
func JudgeEV06(probes []string, network source.Detection, now time.Time) verdict.Judgement {
	if len(probes) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.no_probe"))
	}
	c := cells(probes[0], 3)
	days, _ := strconv.Atoi(c[2])
	if days == 0 {
		days = 7
	}
	if network.Last.IsZero() || now.Sub(network.Last) > time.Duration(days)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.network_silent", "product", c[0], "days", days))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon1.network_alerts", "product", c[0], "count", network.Count, "date", day(network.Last)))
}

// JudgeEV08 needs every query limit of P-07 (`sistema | perfil | umbral | ventana | reglas`) watched by a
// loaded threshold rule.
func JudgeEV08(m *source.Manager, rows []string) verdict.Judgement {

	var unwatched, watched []catalog.Message
	for _, row := range rows {
		c := cells(row, 5)
		ranges, err := opmon1.ParseRules(c[4])
		if err != nil || len(ranges) == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon1.bad_rules", "name", c[0], "rules", c[4]))
		}
		n := 0
		for _, r := range opmon1.Alerting(m.Rules, ranges) {
			if r.Frequency > 0 {
				n++
			}
		}
		name := c[0] + " " + c[1]
		if n == 0 {
			unwatched = append(unwatched, catalog.Says("item.name_detail", "name", name, "detail", c[4]))
		} else {
			watched = append(watched, catalog.Says("opmon1.item_rules", "name", name, "count", n))
		}
	}
	if len(unwatched) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.queries_unwatched", "list", unwatched))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.queries_watched", "list", watched))
}

// JudgeEV09 needs every recipient of P-08 (`destinatario | canal | nivel`) reached by its channel: `correo`
// through the manager's email notification, anything else by an integration of that name, at the level.
func JudgeEV09(m *source.Manager, rows []string) verdict.Judgement {

	var unreached []catalog.Message
	for _, row := range rows {
		c := cells(row, 3)
		level, _ := strconv.Atoi(c[2])
		ok := false
		if strings.EqualFold(c[1], "correo") {
			ok = m.Email.Enabled && len(m.Email.To) > 0 && (level == 0 || m.Email.Level <= level)
		} else {
			ok = slices.ContainsFunc(m.Integrations, func(i source.Integration) bool {
				return strings.EqualFold(i.Name, c[1]) && (level == 0 || i.Level <= level)
			})
		}
		if !ok {
			unreached = append(unreached, catalog.Says("item.name_detail", "name", c[0], "detail", c[1]))
		}
	}
	if len(unreached) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.recipients_unreached", "list", unreached))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.recipients_reached", "count", len(rows)))
}

// Inspection kinds of P-09 and P-10.
const (
	KindConfiguration   = "configuracion"
	KindVulnerabilities = "vulnerabilidades"
	KindPentest         = "pentest"
)

// Kind normalises an inspection kind: `configuración` and `configuracion` are one.
func Kind(s string) string {
	return strings.NewReplacer("á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// Plan is the periodicity in days of each inspection kind of P-09 (`tipo | periodicidad_dias | ejecutor`).
func Plan(rows []string) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		c := cells(r, 2)
		if d, err := strconv.Atoi(c[1]); err == nil && d > 0 {
			out[Kind(c[0])] = d
		}
	}
	return out
}

// Done are the rows of P-10 (`fecha | tipo | alcance | ejecutor | hallazgos | estado`) of one kind, as
// passes.Review reads them.
func Done(rows []string, kind string) []string {
	var out []string
	for _, r := range rows {
		if Kind(cells(r, 2)[1]) == kind {
			out = append(out, r)
		}
	}
	return out
}

// JudgeInspection judges one kind of inspection: continuous when Wazuh does it on the machine, else the
// newest row of its kind within the days of P-09.
func JudgeInspection(continuous bool, continuousWhy catalog.Message, register []string, registerProblem catalog.Message, kind string, plan map[string]int, now time.Time) verdict.Judgement {

	if continuous {
		return verdict.Explain(verdict.Compliant, "", continuousWhy)
	}
	days, ok := plan[kind]
	if !ok {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon3.no_periodicity", "kind", kind))
	}
	j, _ := passes.Review(Done(register, kind), registerProblem, "P-10", days, catalog.Message{}, "P-09", now)
	return j
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

// JudgeEV07 needs every CDB list P-06 (`servicio | proveedor | alcance | listas`) feeds with indicators
// updated on the manager within the days of P-11.
func JudgeEV07(manager *fact.WazuhAgentConfig, rows []string, days int, now time.Time) verdict.Judgement {

	var wanted []string
	for _, r := range rows {
		for _, l := range strings.Split(cells(r, 4)[3], ",") {
			if l = strings.TrimSpace(l); l != "" {
				wanted = append(wanted, l)
			}
		}
	}
	switch {
	case len(wanted) == 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.no_lists"))
	case manager == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	}
	var stale []string
	for _, name := range wanted {
		i := slices.IndexFunc(manager.Lists, func(l fact.CDBList) bool { return l.Name == name || strings.HasSuffix(l.Name, "/"+name) })
		if i < 0 {
			stale = append(stale, name)
			continue
		}
		t, err := time.Parse(time.RFC3339, manager.Lists[i].Modified)
		if err != nil || now.Sub(t) > time.Duration(days)*24*time.Hour {
			stale = append(stale, name)
		}
	}
	if len(stale) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon3.lists_stale", "days", days, "list", stale))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon3.lists_fresh", "count", len(wanted), "days", days))
}

// Package opnub1 judges op.nub.1, cloud services: the logs of the services the organisation uses reaching
// Wazuh, who administers them, and the record of their certification, conformity, tests, encryption and
// jurisdiction.
package opnub1

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Positions of P-01.
const (
	User     = "usuario"
	Provider = "prestador"
	Both     = "ambos"
	Neither  = "ninguna"
)

// ModuleGroups are the rule groups Wazuh gives the alerts of each cloud module.
var ModuleGroups = map[string][]string{
	"aws-s3":     {"amazon", "aws"},
	"azure-logs": {"azure"},
	"gcp-pubsub": {"gcp"},
	"gcp-bucket": {"gcp"},
	"office365":  {"office365"},
	"ms-graph":   {"ms-graph"},
	"github":     {"github"},
}

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

func key(v string) string { return opcont2.Person(v) }

// Used are the services of P-02 (`servicio | modelo | proveedor | informacion | criticidad | uso`) used from
// a third party.
func Used(rows []string) []string {
	var out []string
	for _, r := range rows {
		c := cells(r, 6)
		if c[0] != "" && key(c[5]) != "prestado" {
			out = append(out, c[0])
		}
	}
	return out
}

// Integration is a row of P-06 (`servicio | modulo | ambito`) with a Wazuh module.
type Integration struct {
	Service, Module string
}

func Integrations(rows []string) []Integration {
	var out []Integration
	for _, r := range rows {
		c := cells(r, 2)
		if c[0] != "" && c[1] != "" && key(c[1]) != "ninguno" {
			out = append(out, Integration{Service: c[0], Module: strings.ToLower(c[1])})
		}
	}
	return out
}

// JudgeEV01 needs the logs of every integrated service in Wazuh within maxHours.
func JudgeEV01(integrations []Integration, last map[string]source.Detection, maxHours int, now time.Time) verdict.Judgement {

	if len(integrations) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opnub1.none_integrated"))
	}
	var silent, flowing []catalog.Message
	for _, in := range integrations {
		if _, known := ModuleGroups[in.Module]; !known {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opnub1.unknown_module", "name", in.Service, "module", in.Module))
		}
		d := last[in.Module]
		if d.Last.IsZero() || now.Sub(d.Last) > time.Duration(maxHours)*time.Hour {
			silent = append(silent, catalog.Says("item.name_detail", "name", in.Service, "detail", in.Module))
		} else {
			flowing = append(flowing, catalog.Says("opnub1.item_logs", "name", in.Service, "module", in.Module, "date", day(d.Last)))
		}
	}
	if len(silent) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opnub1.logs_silent", "hours", maxHours, "list", silent))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opnub1.logs_flowing", "list", flowing))
}

// JudgeEV04 needs every actor of a successful administrative operation of an integrated service in P-11
// (`servicio | identidad`).
func JudgeEV04(integrations []Integration, operations []source.CloudOperation, admins []string) verdict.Judgement {

	readable := source.CloudAdminModules()
	var unread []string
	modules := map[string][]string{}
	for _, in := range integrations {
		if !slices.Contains(readable, in.Module) {
			unread = append(unread, in.Service+" ("+in.Module+")")
			continue
		}
		modules[in.Module] = append(modules[in.Module], key(in.Service))
	}
	if len(unread) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opnub1.admins_unread", "list", unread))
	}

	allowed := map[string]bool{}
	for _, r := range admins {
		c := cells(r, 2)
		allowed[key(c[0])+"|"+strings.ToLower(c[1])] = true
	}

	var unknown []catalog.Message
	checked := 0
	for _, op := range operations {
		services, ok := modules[op.Module]
		if !ok || op.Actor == "" {
			continue
		}
		checked += op.Count
		if !slices.ContainsFunc(services, func(s string) bool { return allowed[s+"|"+strings.ToLower(op.Actor)] }) {
			unknown = append(unknown, catalog.Says("opnub1.item_admin", "actor", op.Actor, "operation", op.Operation, "count", op.Count, "module", op.Module))
		}
	}
	if len(unknown) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opnub1.admins_unknown", "list", unknown))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opnub1.admins_known", "count", checked))
}

// rowsOf indexes rows by their first column.
func rowsOf(rows []string, n int) map[string][]string {
	out := map[string][]string{}
	for _, r := range rows {
		c := cells(r, n)
		out[key(c[0])] = c
	}
	return out
}

// valid tells whether a date column holds a date not past.
func valid(c []string, col int, now time.Time) bool {
	t, ok := opcont2.Date(c[col])
	return ok && !t.Before(now)
}

// JudgeEV08 needs every used service certified in P-04 (`servicio | metodologia | certificado | vigencia`)
// and the certification in force.
func JudgeEV08(used, certifications []string, now time.Time) verdict.Judgement {
	certified := rowsOf(certifications, 4)
	var lacking []string
	for _, s := range used {
		c, ok := certified[key(s)]
		if !ok || c[2] == "" || !valid(c, 3, now) {
			lacking = append(lacking, s)
		}
	}
	if len(lacking) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opnub1.uncertified", "list", lacking))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opnub1.certified", "count", len(used)))
}

// Record is what P-03, P-08, P-09 and P-10 say of the used services.
type Record struct {
	Conformity, Jurisdiction, Encryption, Pentests []string
	PentestMonths                                  int
}

// JudgeEV09 needs, for every used service, its ENS conformity in force (P-03 `servicio | conformidad |
// alcance | vigencia | referencia`), a pentest within the months (P-10 `servicio | informe | fecha |
// alcance`), its encryption (P-09) and its data location (P-08).
func JudgeEV09(used []string, r Record, now time.Time) verdict.Judgement {

	conformity, jurisdiction, encryption := rowsOf(r.Conformity, 5), rowsOf(r.Jurisdiction, 2), rowsOf(r.Encryption, 2)
	pentests := map[string]time.Time{}
	for _, row := range r.Pentests {
		c := cells(row, 3)
		if t, ok := opcont2.Date(c[2]); ok && t.After(pentests[key(c[0])]) {
			pentests[key(c[0])] = t
		}
	}

	var lacking []catalog.Message
	for _, s := range used {
		var missing []string
		if c, ok := conformity[key(s)]; !ok || c[1] == "" || !valid(c, 3, now) {
			missing = append(missing, "conformidad")
		}
		if t := pentests[key(s)]; t.IsZero() || t.AddDate(0, r.PentestMonths, 0).Before(now) {
			missing = append(missing, "pentest")
		}
		if c, ok := encryption[key(s)]; !ok || c[1] == "" {
			missing = append(missing, "cifrado")
		}
		if c, ok := jurisdiction[key(s)]; !ok || c[1] == "" {
			missing = append(missing, "jurisdicción")
		}
		if len(missing) > 0 {
			lacking = append(lacking, catalog.Says("item.name_list", "name", s, "list", missing))
		}
	}
	if len(lacking) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opnub1.record_incomplete", "list", lacking))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opnub1.record_complete", "count", len(used)))
}

// Decisions leave out the requirements of the position P-01 does not take.
func Decisions(position string, requirements []string) map[string]verdict.Judgement {

	position = key(position)
	provides := position == Provider || position == Both
	uses := position == User || position == Both

	out := map[string]verdict.Judgement{}
	for _, id := range requirements {
		applies := uses
		if id == "op.nub.1.1" {
			applies = provides
		}
		if id == "op.nub.1.r2.1" {
			applies = provides || uses
		}
		if !applies {
			out[id] = verdict.Explain(verdict.NotApplicable, "", catalog.Says("opnub1.position", "position", position))
		}
	}
	return out
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

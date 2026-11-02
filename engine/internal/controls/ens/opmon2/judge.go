package opmon2

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

const (
	ScopeMetrics   = "metricas"
	ScopeResources = "recursos"
)

func Validators(rows []string, scope string) []string {
	var out []string
	for _, r := range rows {
		c := passes.Cells(r, 3)
		s := strings.ToLower(c[2])
		if c[0] != "" && (s == scope || s == "ambos" || s == "") {
			out = append(out, strings.ToLower(c[0]))
		}
	}
	return out
}

func Cycles(rows []string, validators []string, resources bool) []string {
	var out []string
	for _, r := range rows {
		c := passes.Cells(r, 7)
		if !slices.Contains(validators, strings.ToLower(c[3])) {
			continue
		}
		if resources && (c[4] == "" || c[5] == "" || c[6] == "") {
			continue
		}
		out = append(out, r)
	}
	return out
}

var Indicators = map[string]func(opexp7.Incident) bool{
	"incidentes_por_tipo":      func(in opexp7.Incident) bool { return in.Field(func(p opexp7.Phase) string { return p.Class }) != "" },
	"incidentes_por_severidad": func(in opexp7.Incident) bool { return in.Severity() != "" },
	"tiempo_medio_contencion":  func(in opexp7.Incident) bool { return in.Has("intermedio") || in.Has("final") },
	"tiempo_medio_resolucion":  func(in opexp7.Incident) bool { return in.Has("inicial") },
	"notificados_ccn_cert":     func(in opexp7.Incident) bool { return in.Field(func(p opexp7.Phase) string { return p.CCNCERT }) != "" },
	"notificados_aepd": func(in opexp7.Incident) bool {
		return in.Field(func(p opexp7.Phase) string { return p.Personal }) != ""
	},
}

func JudgeEV03(incidents []opexp7.Incident, indicators []string) verdict.Judgement {

	var unknown []string
	for _, name := range indicators {
		if _, ok := Indicators[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon2.unknown_indicators", "list", unknown))
	}

	var lacking []catalog.Message
	for _, in := range incidents {
		var missing []string
		for _, name := range indicators {
			if !Indicators[name](in) {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			lacking = append(lacking, catalog.Says("item.name_list", "name", in.ID, "list", missing))
		}
	}
	if len(lacking) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon2.incidents_lacking", "list", lacking))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon2.incidents_measured", "count", len(incidents), "indicators", len(indicators)))
}

func JudgeEV04(reporting *source.Reporting, pass *fact.AgentPass, windowStart time.Time) verdict.Judgement {

	switch {
	case reporting == nil || reporting.Status != "active":
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon1.not_reporting"))
	case pass == nil:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon2.no_pass", "date", day(windowStart)))
	}
	t, _ := time.Parse(time.RFC3339, pass.TS)
	if t.Before(windowStart) {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opmon2.no_pass", "date", day(windowStart)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opmon2.measured", "date", day(t)))
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

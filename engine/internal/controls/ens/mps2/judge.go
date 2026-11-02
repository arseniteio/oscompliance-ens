package mps2

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

var Attacks = []struct{ Name, Evidence string }{
	{"acceso_sin_autenticacion", "EV-02"},
	{"via_alternativa", "EV-03"},
	{"manipulacion_de_url", "EV-04"},
	{"manipulacion_de_cookies", "EV-05"},
	{"inyeccion", "EV-06"},
	{"escalado_de_privilegios", "EV-07"},
	{"xss", "EV-08"},
}

func JudgeEV10(vulnerabilities []source.VulnerabilityDay, days int, now time.Time) verdict.Judgement {
	var old []string
	open := 0
	for _, v := range vulnerabilities {
		severity := strings.ToLower(v.Severity)
		if severity != "critical" && severity != "high" {
			continue
		}
		open += v.Count
		if now.Sub(v.Detected) > time.Duration(days)*24*time.Hour {
			old = append(old, v.Detected.Format("2006-01-02")+" "+v.Severity+" ×"+strconv.Itoa(v.Count)+" "+strings.Join(v.Examples, " "))
		}
	}
	if len(old) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps2.vulnerabilities_old", "days", days, "list", old))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps2.vulnerabilities", "count", open, "days", days))
}

const (
	BlackBox = "caja_negra"
	WhiteBox = "caja_blanca"
)

func Modality(v string) string {
	switch m := strings.ReplaceAll(opcont2.Person(v), " ", "_"); {
	case m == "r1" || strings.Contains(m, "negra"):
		return BlackBox
	case m == "r2" || strings.Contains(m, "blanca"):
		return WhiteBox
	default:
		return m
	}
}

func JudgeEV11(apps []string, audits []string, modality string, days int, now time.Time) verdict.Judgement {

	var lacking []catalog.Message
	for _, app := range apps {
		var newest time.Time
		complete := false
		for _, r := range audits {
			c := cells(r, 6)
			t, ok := opcont2.Date(c[0])
			if !ok || t.After(now) || !strings.EqualFold(c[1], app) || Modality(c[2]) != modality || !t.After(newest) {
				continue
			}
			newest, complete = t, modality != WhiteBox || (c[3] != "" && c[4] != "")
		}
		switch {
		case newest.IsZero() || now.Sub(newest) > time.Duration(days)*24*time.Hour:
			lacking = append(lacking, catalog.Raw(app))
		case !complete:
			lacking = append(lacking, catalog.Says("mps2.item_no_method", "name", app))
		}
	}
	if len(lacking) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps2.audits_missing", "modality", strings.ReplaceAll(modality, "_", " "), "days", days, "list", lacking))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps2.audited", "count", len(apps), "modality", strings.ReplaceAll(modality, "_", " "), "days", days))
}

func JudgeEV12(apps []string, findings []string, now time.Time) verdict.Judgement {
	var late []string
	checked := 0
	for _, r := range findings {
		c := cells(r, 6)
		if !slices.ContainsFunc(apps, func(a string) bool { return strings.EqualFold(a, c[1]) }) {
			continue
		}
		checked++
		state := opcont2.Person(c[5])
		deadline, ok := opcont2.Date(c[4])
		if state != "resuelto" && state != "cerrado" && (!ok || deadline.Before(now)) {
			late = append(late, c[0]+" ("+c[1]+")")
		}
	}
	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps2.findings_late", "list", late))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps2.findings", "count", checked))
}

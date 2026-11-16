package mpsw2

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

type App struct {
	Name     string
	Machines []string
	Packages []string
}

func names(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func AppsOf(rows []string, machine string) []App {
	var out []App
	for _, r := range rows {
		c := cells(r, 3)
		a := App{Name: c[0], Machines: names(c[1]), Packages: names(c[2])}
		if slices.ContainsFunc(a.Machines, func(m string) bool { return strings.EqualFold(m, machine) }) {
			out = append(out, a)
		}
	}
	return out
}

type Deployment struct {
	App, Package, Version string
	Time                  time.Time
}

func (d Deployment) String() string {
	return d.App + " " + d.Package + " " + d.Version + " (" + d.Time.Format("2006-01-02 15:04") + ")"
}

func Deployments(apps []App, installed map[string]time.Time) []Deployment {
	var out []Deployment
	for key, t := range installed {
		pkg, version, _ := strings.Cut(key, " ")
		for _, a := range apps {
			if slices.Contains(a.Packages, pkg) {
				out = append(out, Deployment{App: a.Name, Package: pkg, Version: version, Time: t})
			}
		}
	}
	slices.SortFunc(out, func(a, b Deployment) int { return a.Time.Compare(b.Time) })
	return out
}

func JudgeEV01(apps []App, deployments []Deployment) verdict.Judgement {
	var unpackaged []string
	for _, a := range apps {
		if len(a.Packages) == 0 {
			unpackaged = append(unpackaged, a.Name)
		}
	}
	if len(unpackaged) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.no_packages", "list", unpackaged))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.deployments", "apps", len(apps), "count", len(deployments)))
}

func JudgeEV02(deployments []Deployment, acceptances []string) verdict.Judgement {
	var unaccepted []string
	for _, d := range deployments {
		if !slices.ContainsFunc(acceptances, func(r string) bool {
			c := cells(r, 5)
			t, ok := opcont2.Date(c[0])
			return ok && !t.After(d.Time) && strings.EqualFold(c[1], d.App) && opcont2.Person(c[3]) == "aceptada" && c[4] != "" &&
				(c[2] == "" || strings.HasPrefix(d.Version, c[2]))
		}) {
			unaccepted = append(unaccepted, d.String())
		}
	}
	if len(unaccepted) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.unaccepted", "list", unaccepted))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.accepted", "count", len(deployments)))
}

func JudgeEV03(deployments []Deployment, regressions []source.SCARegression, days int) verdict.Judgement {
	var worse []string
	for _, r := range regressions {
		if slices.ContainsFunc(deployments, func(d Deployment) bool {
			return !r.Time.Before(d.Time) && r.Time.Sub(d.Time) <= time.Duration(days)*24*time.Hour
		}) {
			worse = append(worse, r.CheckID+" "+r.Title)
		}
	}
	if len(worse) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.regressions", "days", days, "list", worse))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.no_regressions", "count", len(deployments), "days", days))
}

func JudgeEV04(sockets []fact.ListeningSocket, apps []App, declared []string) verdict.Judgement {
	allowed := map[int]bool{}
	for _, r := range declared {
		c := cells(r, 2)
		if c[0] != "*" && !slices.ContainsFunc(apps, func(a App) bool { return strings.EqualFold(a.Name, c[0]) }) {
			continue
		}
		if p, err := strconv.Atoi(c[1]); err == nil {
			allowed[p] = true
		}
	}
	var undeclared []string
	for _, s := range sockets {
		if strings.HasPrefix(s.Address, "127.") || s.Address == "::1" || allowed[s.Port] {
			continue
		}
		item := s.Protocol + "/" + strconv.Itoa(s.Port)
		if s.Process != "" {
			item += " (" + s.Process + ")"
		}
		if !slices.Contains(undeclared, item) {
			undeclared = append(undeclared, item)
		}
	}
	if len(undeclared) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.undeclared_ports", "list", undeclared))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.declared_ports", "count", len(allowed)))
}

func JudgeEV05(apps []App, vulnerabilities []source.PackageVulnerability) verdict.Judgement {
	var found []string
	for _, v := range vulnerabilities {
		for _, a := range apps {
			if slices.Contains(a.Packages, v.Package) {
				found = append(found, a.Name+": "+v.Package+" "+v.Severity+" "+strings.Join(v.CVEs, " "))
			}
		}
	}
	if len(found) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.vulnerable", "list", found))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.not_vulnerable", "count", len(apps)))
}

func JudgeEV07(deployments []Deployment, preproduction string, installed map[string]time.Time) verdict.Judgement {
	if preproduction == "" {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.no_preproduction"))
	}
	var skipped []string
	for _, d := range deployments {
		t, ok := installed[d.Package+" "+d.Version]
		if !ok || t.After(d.Time) {
			skipped = append(skipped, d.String())
		}
	}
	if len(skipped) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpsw2.not_preproduced", "machine", preproduction, "list", skipped))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpsw2.preproduced", "machine", preproduction, "count", len(deployments)))
}

func Earliest(sources ...map[string]time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	for _, src := range sources {
		for version, t := range src {
			if old, ok := out[version]; !ok || t.Before(old) {
				out[version] = t
			}
		}
	}
	return out
}

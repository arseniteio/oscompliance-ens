package mps2

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestVulnerabilities(t *testing.T) {
	v := []source.VulnerabilityDay{{Severity: "Critical", Detected: now.AddDate(0, 0, -40), Count: 2, Examples: []string{"CVE-2026-1"}}, {Severity: "Medium", Detected: now.AddDate(-1, 0, 0), Count: 9}}
	check(t, "old", JudgeEV10(v, 30, now), verdict.NonCompliant, "", "CVE-2026-1")
	check(t, "fresh", JudgeEV10(v, 60, now), verdict.Compliant, "", "2")
}

func TestAudits(t *testing.T) {
	if Modality("R2") != WhiteBox || Modality("Caja negra") != BlackBox {
		t.Error("modality")
	}
	audits := []string{"2026-06-01 | sede | caja blanca | OWASP ASVS | SonarQube, ZAP | 3", "2026-09-01 | portal | caja blanca | | | 1"}
	check(t, "audited", JudgeEV11([]string{"sede"}, audits, WhiteBox, 365, now), verdict.Compliant, "", "1")
	check(t, "no method", JudgeEV11([]string{"portal"}, audits, WhiteBox, 365, now), verdict.NonCompliant, "", "portal")
	check(t, "late", JudgeEV11([]string{"sede"}, audits, WhiteBox, 90, now), verdict.NonCompliant, "", "sede")
	check(t, "other modality", JudgeEV11([]string{"sede"}, audits, BlackBox, 365, now), verdict.NonCompliant, "", "sede")
}

func TestFindings(t *testing.T) {
	findings := []string{"XSS en búsqueda | sede | alta | equipo web | 2026-10-01 | abierto", "SQLi | sede | crítica | equipo web | 2026-09-01 | resuelto", "CSRF | otra | media | x | 2026-01-01 | abierto"}
	check(t, "late", JudgeEV12([]string{"sede"}, findings, now), verdict.NonCompliant, "", "XSS")
	check(t, "solved", JudgeEV12([]string{"sede"}, findings[1:], now), verdict.Compliant, "", "1")
}

func TestCatalogAttacks(t *testing.T) {
	c, _ := catalog.LookupControl(control)
	for _, option := range c.Parameters["P-03"].Columns[0].Options {
		key := strings.ReplaceAll(opcont2.Person(option), " ", "_")
		if !slices.ContainsFunc(Attacks, func(a struct{ Name, Evidence string }) bool { return a.Name == key }) {
			t.Errorf("option %q (%s) judged by no evidence", option, key)
		}
	}
}

package mpsw2

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var apps = AppsOf([]string{"portal | web01, web02 | portal-app, nginx | J. Ruiz | propio", "otra | db01 | postgresql | | terceros"}, "WEB01")

var deployments = Deployments(apps, map[string]time.Time{
	"portal-app 2.4.0": time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC),
	"curl 8.5":         time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC),
})

func TestDeployments(t *testing.T) {
	if len(apps) != 1 || len(deployments) != 1 || deployments[0].Version != "2.4.0" {
		t.Fatalf("apps %v deployments %v", apps, deployments)
	}
	check(t, "known", JudgeEV01(apps, deployments), verdict.Compliant, "", "1")
	check(t, "unpackaged", JudgeEV01([]App{{Name: "x"}}, nil), verdict.NonCompliant, "", "x")
}

func TestAcceptance(t *testing.T) {
	check(t, "accepted", JudgeEV02(deployments, []string{"2026-10-15 | portal | 2.4 | aceptada | RSI"}), verdict.Compliant, "", "1")
	check(t, "after", JudgeEV02(deployments, []string{"2026-10-25 | portal | 2.4 | aceptada | RSI"}), verdict.NonCompliant, "", "portal-app 2.4.0")
	check(t, "rejected", JudgeEV02(deployments, []string{"2026-10-15 | portal | | rechazada | RSI"}), verdict.NonCompliant, "", "")
}

func TestDeterioration(t *testing.T) {
	regressions := []source.SCARegression{{CheckID: "28500", Title: "Ensure SSH root login is disabled", Time: time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)}}
	check(t, "regression", JudgeEV03(deployments, regressions, 7), verdict.NonCompliant, "", "28500")
	check(t, "outside window", JudgeEV03(deployments, regressions, 1), verdict.Compliant, "", "")

	sockets := []fact.ListeningSocket{{Protocol: "tcp", Address: "0.0.0.0", Port: 443, Process: "nginx"}, {Protocol: "tcp", Address: "0.0.0.0", Port: 8080, Process: "java"}, {Protocol: "tcp", Address: "127.0.0.1", Port: 5432}}
	check(t, "undeclared", JudgeEV04(sockets, apps, []string{"portal | 443 | https", "* | 22 | ssh"}), verdict.NonCompliant, "", "8080 (java)")
	check(t, "declared", JudgeEV04(sockets[:1], apps, []string{"portal | 443 | https"}), verdict.Compliant, "", "")

	vulns := []source.PackageVulnerability{{Package: "nginx", Severity: "High", CVEs: []string{"CVE-2026-9"}}, {Package: "postgresql", Severity: "Critical"}}
	check(t, "vulnerable", JudgeEV05(apps, vulns), verdict.NonCompliant, "", "CVE-2026-9")
	check(t, "clean", JudgeEV05(apps, vulns[1:]), verdict.Compliant, "", "")
}

func TestPreproduction(t *testing.T) {
	pre := map[string]time.Time{"portal-app 2.4.0": time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)}
	check(t, "preproduced", JudgeEV07(deployments, "pre-web01", pre), verdict.Compliant, "", "pre-web01")
	check(t, "skipped", JudgeEV07(deployments, "pre-web01", nil), verdict.NonCompliant, "", "portal-app")
	check(t, "no pair", JudgeEV07(deployments, "", nil), verdict.NonCompliant, "", "")
}

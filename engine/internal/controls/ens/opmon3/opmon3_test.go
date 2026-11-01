package opmon3

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
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

var manager = &source.Manager{
	Daemons: map[string]string{"wazuh-analysisd": "running", "wazuh-remoted": "running", "wazuh-db": "running"},
	Rules: []source.Rule{
		{ID: 5712, Level: 10, Dir: "ruleset/rules", Frequency: 8, Correlates: true},
		{ID: 100510, Level: 10, Dir: "etc/rules", Frequency: 20, Correlates: true},
		{ID: 100511, Level: 5, Dir: "etc/rules"},
	},
	Email:        source.Email{Enabled: true, To: []string{"soc@example.org"}, Level: 12},
	Integrations: []source.Integration{{Name: "slack", Level: 10}},
}

func TestCollection(t *testing.T) {

	alive := &source.Reporting{LastKeepAlive: now.Add(-10 * time.Minute)}
	check(t, "collecting", JudgeEV01(manager, alive, 1, now), verdict.Compliant, "", "")
	check(t, "not reporting", JudgeEV01(manager, nil, 1, now), verdict.NonCompliant, "", "")

	rows := Sources([]string{"auth | * | /var/log/auth.log | 24", "web | web01 | /var/log/nginx/access.log | 2", "db | db01 | /var/log/mysql.log | 2"}, "WEB01")
	if len(rows) != 2 {
		t.Fatalf("sources of web01: %v", rows)
	}
	config := &fact.WazuhAgentConfig{Status: fact.SourceRead, Localfiles: []fact.AgentLocalfile{{Location: "/var/log/auth.log"}, {Location: "/var/log/nginx/access.log"}}}
	seen := map[string]time.Time{"/var/log/auth.log": now.Add(-time.Hour), "/var/log/nginx/access.log": now.Add(-5 * time.Hour)}
	check(t, "silent source", JudgeEV02(rows, config, seen, now), verdict.NonCompliant, "", "nginx")
	seen["/var/log/nginx/access.log"] = now.Add(-time.Minute)
	check(t, "flowing", JudgeEV02(rows, config, seen, now), verdict.Compliant, "", "auth")
	config.Localfiles = config.Localfiles[:1]
	check(t, "unread", JudgeEV02(rows, config, seen, now), verdict.NonCompliant, "", "nginx")
	check(t, "none declared", JudgeEV02(nil, config, seen, now), verdict.NotEvaluable, verdict.CauseConfiguration, "")
}

func TestManagerJudges(t *testing.T) {

	check(t, "correlating", JudgeEV03(manager, []string{"wazuh | 1", "propias | 1"}), verdict.Compliant, "", "2")
	check(t, "short", JudgeEV03(manager, []string{"propias | 5"}), verdict.NonCompliant, "", "propias")

	check(t, "surface", JudgeEV04(Surface{SCAEnabled: true, SCAResults: 1, Packages: 300, Detector: true}), verdict.Compliant, "", "300")
	check(t, "blind", JudgeEV04(Surface{SCAEnabled: true, Packages: 300}), verdict.NonCompliant, "", "vulnerability-detection")

	check(t, "no probe", JudgeEV06(nil, source.Detection{}, now), verdict.NonCompliant, "", "")
	check(t, "probe", JudgeEV06([]string{"Suricata | TAP | 2"}, source.Detection{Last: now.Add(-time.Hour), Count: 9}, now), verdict.Compliant, "", "Suricata")

	check(t, "watched", JudgeEV08(manager, []string{"BD | gestor | 500 | 1h | 100510"}), verdict.Compliant, "", "BD")
	check(t, "unwatched", JudgeEV08(manager, []string{"BD | gestor | 500 | 1h | 100511"}), verdict.NonCompliant, "", "BD")

	check(t, "reached", JudgeEV09(manager, []string{"RSI | correo | 12", "SOC | slack | 10"}), verdict.Compliant, "", "2")
	check(t, "unreached", JudgeEV09(manager, []string{"RSI | correo | 7", "SOC | teams | 10"}), verdict.NonCompliant, "", "teams")
}

func TestInspections(t *testing.T) {

	plan := Plan([]string{"configuración | 90 | interno", "pentest | 365 | externo"})
	register := []string{"2026-03-01 | pentest | perímetro | Auditora S.L. | 3 | corregido", "2025-01-01 | pentest | web | Auditora S.L. | 1 | corregido"}

	check(t, "continuous", JudgeInspection(true, catalog.Says("opmon3.sca_continuous", "policies", 1), nil, catalog.Message{}, KindConfiguration, plan, now), verdict.Compliant, "", "")
	check(t, "pentest", JudgeInspection(false, catalog.Message{}, register, catalog.Message{}, KindPentest, plan, now), verdict.Compliant, "", "")
	check(t, "pentest overdue", JudgeInspection(false, catalog.Message{}, register[1:], catalog.Message{}, KindPentest, plan, now), verdict.NonCompliant, "", "")
	check(t, "no plan", JudgeInspection(false, catalog.Message{}, register, catalog.Message{}, KindVulnerabilities, plan, now), verdict.NotEvaluable, verdict.CauseConfiguration, "")
}

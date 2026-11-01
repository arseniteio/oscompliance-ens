package opmon1

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

var manager = &source.Manager{
	Daemons: map[string]string{"wazuh-analysisd": "running", "wazuh-remoted": "running", "wazuh-db": "running", "wazuh-modulesd": "running"},
	Rules: []source.Rule{
		{ID: 5710, Level: 5, Dir: "ruleset/rules", File: "0095-sshd_rules.xml"},
		{ID: 5712, Level: 10, Dir: "ruleset/rules", File: "0095-sshd_rules.xml", Frequency: 8, Correlates: true},
		{ID: 5715, Level: 0, Dir: "etc/rules", File: "local_rules.xml"},
		{ID: 100100, Level: 7, Dir: "etc/rules", File: "local_rules.xml"},
	},
	RuleExclude: []string{"0215-policy_rules.xml"},
	Responses:   []source.Response{{Command: "firewall-drop", Rules: "5763"}},
	Version:     "4.14.7-1",
	Installed:   now.AddDate(0, -2, 0),
}

func TestParseRules(t *testing.T) {
	r, err := ParseRules("5710, 5712 80700-80799")
	if err != nil || len(r) != 3 || r[2] != (Range{80700, 80799}) {
		t.Errorf("got %v %v", r, err)
	}
	if _, err := ParseRules("ssh"); err == nil {
		t.Error("a name is not a rule id")
	}
}

func TestJudges(t *testing.T) {

	check(t, "detecting", JudgeEV01(manager, []string{"wazuh | ruleset | 2", "propias | | 1"}), verdict.Compliant, "", "3 rules")
	check(t, "set short", JudgeEV01(manager, []string{"wazuh | | 4500"}), verdict.NonCompliant, "", "wazuh")
	stopped := *manager
	stopped.Daemons = map[string]string{"wazuh-analysisd": "stopped"}
	check(t, "stopped", JudgeEV01(&stopped, nil), verdict.NonCompliant, "", "wazuh-analysisd")

	alive := &source.Reporting{LastKeepAlive: now.Add(-time.Hour)}
	check(t, "covered", JudgeEV02(alive, &fact.WazuhAgentConfig{Status: fact.SourceRead}, 2, now), verdict.Compliant, "", "")
	check(t, "sca off", JudgeEV02(alive, &fact.WazuhAgentConfig{Status: fact.SourceRead, SCADisabled: true}, 2, now), verdict.NonCompliant, "", "sca")
	check(t, "silent", JudgeEV02(&source.Reporting{LastKeepAlive: now.Add(-5 * time.Hour)}, nil, 2, now), verdict.NonCompliant, "", "")
	check(t, "no config", JudgeEV02(alive, nil, 2, now), verdict.NotEvaluable, verdict.CauseCollection, "")

	check(t, "no detections", JudgeEV03(source.Detection{Last: now.AddDate(0, 0, -9)}, 7, now), verdict.NonCompliant, "", "7")
	check(t, "detections", JudgeEV03(source.Detection{Last: now.Add(-time.Hour), Count: 40}, 7, now), verdict.Compliant, "", "40")

	check(t, "blind", JudgeEV04(manager, []string{"ssh | linux | 5710-5712", "web | | 31100"}), verdict.NonCompliant, "", "web")
	check(t, "silenced does not cover", JudgeEV04(manager, []string{"login | | 5715"}), verdict.NonCompliant, "", "login")
	check(t, "bad rules", JudgeEV04(manager, []string{"ssh | | ssh"}), verdict.NotEvaluable, verdict.CauseConfiguration, "")

	check(t, "network not needed", JudgeEV05("no | | sin segmentos expuestos", source.Detection{}, 7, now), verdict.Compliant, "", "")
	check(t, "network silent", JudgeEV05("sí | Suricata | DMZ", source.Detection{}, 7, now), verdict.NonCompliant, "", "Suricata")

	check(t, "responses", JudgeEV07(manager, []string{"firewall-drop | 5763 | agente | 600"}, 2), verdict.Compliant, "", "")
	check(t, "response missing", JudgeEV07(manager, []string{"disable-account | 5712 | agente | 600"}, 0), verdict.NonCompliant, "", "disable-account")

	check(t, "silenced unapproved", JudgeEV08(manager, []string{"0215-policy_rules.xml | de fábrica | RSI"}, 180, now), verdict.NonCompliant, "", "5715")
	check(t, "current", JudgeEV08(manager, []string{"0215-policy_rules.xml | de fábrica | RSI", "5715 | ruido | RSI"}, 180, now), verdict.Compliant, "", "4.14.7")
	check(t, "old", JudgeEV08(manager, nil, 30, now), verdict.NonCompliant, "", "")
}

func TestReportingOf(t *testing.T) {
	if r := ReportingOf("000", nil, manager, now); r == nil || !r.LastKeepAlive.Equal(now) {
		t.Errorf("manager: %v", r)
	}
	if r := ReportingOf("001", nil, manager, now); r != nil {
		t.Errorf("agent without record: %v", r)
	}
}

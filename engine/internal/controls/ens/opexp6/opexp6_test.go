package opexp6

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func clam() *fact.MalwareProtection {
	return &fact.MalwareProtection{Status: fact.SourceRead, Products: []fact.Antimalware{{Product: "clamav", Running: true}},
		Signatures: "2026-10-29T06:24:00Z", LastScan: "2026-10-27T03:00:00Z", Allowlist: "absent", Responses: []string{"firewall-drop"},
		Settings: []string{"actualizacion_automatica_firmas", "analisis_comprimidos", "registro_syslog"}}
}

func TestAntimalware(t *testing.T) {

	check(t, "running", JudgeEV01(clam(), []string{"clamav"}, false, catalog.Message{}), verdict.Compliant, "", "clamav")
	check(t, "expected other", JudgeEV01(clam(), []string{"mdatp"}, false, catalog.Message{}), verdict.NonCompliant, "", "mdatp")
	check(t, "none", JudgeEV01(&fact.MalwareProtection{Status: fact.SourceRead}, nil, false, catalog.Message{}), verdict.NonCompliant, "", "no antimalware")
	bare := &fact.MalwareProtection{Status: fact.SourceRead}
	check(t, "wazuh declared and installed", JudgeEV01(bare, []string{"Wazuh"}, true, catalog.Message{}), verdict.Compliant, "", "wazuh")
	check(t, "wazuh declared, not installed", JudgeEV01(bare, []string{"wazuh"}, false, catalog.Message{}), verdict.NonCompliant, "", "no antimalware")
	check(t, "wazuh installed, not declared", JudgeEV01(bare, []string{"clamav"}, true, catalog.Message{}), verdict.NonCompliant, "", "no antimalware")
	check(t, "wazuh-agent counts as wazuh", JudgeEV01(clam(), []string{"clamav", "wazuh-agent"}, true, catalog.Message{}), verdict.Compliant, "", "wazuh")

	check(t, "signatures", JudgeEV02(clam(), 24, catalog.Message{}, now), verdict.Compliant, "", "2026-10-29 06:24")
	check(t, "old signatures", JudgeEV02(clam(), 2, catalog.Message{}, now), verdict.NonCompliant, "", "5 h ago")
	falcon := &fact.MalwareProtection{Status: fact.SourceRead, Products: []fact.Antimalware{{Product: "falcon-sensor", Running: true}}}
	check(t, "unread product", JudgeEV02(falcon, 24, catalog.Message{}, now), verdict.NotEvaluable, verdict.CauseCollection, "falcon-sensor")
	defender := &fact.MalwareProtection{Status: fact.SourceRead, Products: []fact.Antimalware{{Product: "windows-defender", Running: true}}, Signatures: "2026-10-29T06:24:00.0000000Z"}
	check(t, "defender signatures", JudgeEV02(defender, 24, catalog.Message{}, now), verdict.Compliant, "", "2026-10-29 06:24")

	check(t, "settings", JudgeEV03(clam(), []string{"proteccion_tiempo_real | si", "analisis_comprimidos | si"}, catalog.Message{}), verdict.NonCompliant, "", "proteccion_tiempo_real")
	check(t, "unknown setting", JudgeEV03(clam(), []string{"heuristica | si"}, catalog.Message{}), verdict.NotEvaluable, verdict.CauseConfiguration, "heuristica")

	check(t, "scan", JudgeEV05(clam(), 7, catalog.Message{}, now), verdict.Compliant, "", "2026-10-27")
	check(t, "scan old", JudgeEV05(clam(), 1, catalog.Message{}, now), verdict.NonCompliant, "", "2 days ago")
}

func TestJudgeEV04(t *testing.T) {

	found := []source.AlertCount{{Rule: ruleDetection, Count: 1, Examples: []string{"/tmp/eicar.com"}}}
	check(t, "detection", JudgeEV04(clam(), found), verdict.Compliant, "", "/tmp/eicar.com")
	check(t, "repeated", JudgeEV04(clam(), append(found, source.AlertCount{Rule: ruleRepeated, Count: 1})), verdict.NonCompliant, "", "not resolved")
	quiet := clam()
	quiet.Settings = []string{"analisis_comprimidos"}
	check(t, "blind", JudgeEV04(quiet, nil), verdict.NotEvaluable, verdict.CauseCollection, "LogSyslog")
}

func TestStartAndEDR(t *testing.T) {

	c := &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscheckScanOnStart: true, Directories: []fact.FIMDirectory{{Path: "/etc"}, {Path: "/boot"}}, ActiveResponses: []string{"firewall-drop"}}
	check(t, "start", JudgeEV06(c, []string{"/boot", "/etc/ssh"}, catalog.Message{}), verdict.Compliant, "", "2 paths")
	check(t, "start gap", JudgeEV06(c, []string{"/lib/modules"}, catalog.Message{}), verdict.NonCompliant, "", "/lib/modules")

	check(t, "allowlist", JudgeEV07(clam()), verdict.NonCompliant, "", "not installed")

	on := Capabilities([]string{"virustotal | si | FIM", "yara | no |", "rootcheck | si | todos", "active_response | si | firewall-drop"})
	manager := &fact.WazuhAgentConfig{Status: fact.SourceRead, Integrations: []string{"virustotal"}}
	check(t, "virustotal", JudgeEV08(on["virustotal"], manager, c, nil), verdict.Compliant, "", "VirusTotal")
	check(t, "no integration", JudgeEV08(true, &fact.WazuhAgentConfig{Status: fact.SourceRead}, c, nil), verdict.NonCompliant, "", "no VirusTotal")
	check(t, "yara off", JudgeEV09(on["yara"], clam()), verdict.NonCompliant, "", "does not activate yara")
	check(t, "rootcheck", JudgeEV10(on["rootcheck"], c), verdict.Compliant, "", "rootcheck runs")
	check(t, "responses", JudgeEV11(on["active_response"], c, clam()), verdict.Compliant, "", "firewall-drop")
	nobin := clam()
	nobin.Responses = nil
	check(t, "script missing", JudgeEV11(true, c, nobin), verdict.NonCompliant, "", "firewall-drop")
}

func TestJudgeEV12(t *testing.T) {

	usb := []source.AlertCount{{Rule: "81101", Count: 2}}
	check(t, "blocked", JudgeEV12("bloqueados", catalog.Message{}, usb, clam()), verdict.NonCompliant, "", "2 USB")
	check(t, "unscanned", JudgeEV12("analisis", catalog.Message{}, usb, clam()), verdict.NonCompliant, "", "without real-time")
	check(t, "quiet", JudgeEV12("bloqueados", catalog.Message{}, nil, clam()), verdict.Compliant, "", "0 USB")
	check(t, "bad policy", JudgeEV12("a veces", catalog.Message{}, nil, clam()), verdict.NotEvaluable, verdict.CauseConfiguration, "a veces")
}

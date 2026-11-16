package mps4

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestMachine(t *testing.T) {
	d := &fact.DeviceSecurity{Status: fact.SourceRead, LoadPercent: 40, MemoryPercent: 60, SynCookies: true}
	check(t, "headroom", JudgeEV01(d, 70), verdict.Compliant, "", "")
	check(t, "no headroom", JudgeEV01(d, 50), verdict.NonCompliant, "", "60")

	drop := &fact.FirewallSnapshot{Status: fact.SourceRead, Chains: []fact.FirewallChain{{Hook: "input", Policy: "drop"}}}
	check(t, "prevention", JudgeEV02(d, drop), verdict.Compliant, "", "")
	d.SynCookies = false
	check(t, "no cookies", JudgeEV02(d, &fact.FirewallSnapshot{Status: fact.SourceRead}), verdict.NonCompliant, "", "syncookies, firewall")

	sockets := []fact.ListeningSocket{{Protocol: "udp", Address: "0.0.0.0", Port: 123}, {Protocol: "udp", Address: "127.0.0.53", Port: 53}, {Protocol: "tcp", Address: "0.0.0.0", Port: 53}}
	check(t, "amplifier", JudgeEV09(sockets, nil), verdict.NonCompliant, "", "ntp")
	check(t, "allowed", JudgeEV09(sockets, []string{"ntp"}), verdict.Compliant, "", "")
}

func TestManagerAndEpisodes(t *testing.T) {
	m := &source.Manager{Rules: []source.Rule{{ID: 100500, Level: 10}}, Responses: []source.Response{{Command: "firewall-drop", Rules: "5763,100500"}}}
	rules := DoSRules(m, []string{"denegación de servicio | inundación HTTP | nginx | 100500"})
	check(t, "containment", JudgeEV07(m, rules), verdict.Compliant, "", "firewall-drop")
	check(t, "no containment", JudgeEV07(m, []string{"1"}), verdict.NonCompliant, "", "")

	episodes := []string{"2026-10-02T10:00 | 2026-10-02T11:00 | sede | inundación HTTP | alto | bloqueo de rangos | ", "2026-10-09T10:00 | 2026-10-09T10:20 | sede | | bajo | | "}
	check(t, "untold", JudgeEV06(episodes), verdict.NonCompliant, "", "sede")
	check(t, "incomplete", JudgeEV10(episodes), verdict.NonCompliant, "", "2026-10-09")
}

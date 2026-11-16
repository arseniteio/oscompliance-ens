package mpeq4

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

var devices = ParseDevices([]string{"MFP-03 | multifunción | 10.2.0.14 | AA:BB:CC:00:11:22 | Administración | sí", "router | encaminador | 10.2.0.1 | | Sistemas | no"})

func TestNeighbours(t *testing.T) {
	s := &fact.NeighbourSnapshot{Status: fact.SourceRead, Neighbours: []fact.Neighbour{
		{IP: "10.2.0.1", MAC: "00:00:00:00:00:01"}, {IP: "10.2.0.99", MAC: "aa:bb:cc:00:11:22"}, {IP: "10.2.0.20", MAC: "11:11:11:11:11:11"}, {IP: "10.2.0.50", MAC: "de:ad:be:ef:00:00"},
	}}
	fleet := map[string]bool{"10.2.0.20": true}
	check(t, "unknown", JudgeEV02(s, devices, fleet), verdict.NonCompliant, "", "10.2.0.50")
	s.Neighbours = s.Neighbours[:3]
	check(t, "known", JudgeEV02(s, devices, fleet), verdict.Compliant, "", "3")
	check(t, "no fact", JudgeEV02(nil, devices, fleet), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func TestFlows(t *testing.T) {
	rules := []string{"multifunción | 10.2.0.5 | tcp | 9100", "multifunción | 10.2.0.6 | tcp | 445"}
	flows := []source.Flow{{Source: "10.2.0.5", Destination: "10.2.0.14", Protocol: "tcp", Port: "9100", Count: 30}, {Source: "10.2.0.14", Destination: "8.8.8.8", Protocol: "tcp", Port: "443", Count: 2}}
	check(t, "outside", JudgeEV03(flows, devices, rules), verdict.NonCompliant, "", "8.8.8.8")
	check(t, "allowed", JudgeEV03(flows[:1], devices, rules), verdict.Compliant, "", "30")
}

func TestWipe(t *testing.T) {
	check(t, "wipe", JudgeEV08(devices, []string{"MFP-03 | disco de 320 GB | sobrescritura | tras cada trabajo"}), verdict.Compliant, "", "1")
	check(t, "no wipe", JudgeEV08(devices, nil), verdict.NonCompliant, "", "MFP-03")
}

package mpcom4

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var segments = ParseSegments([]string{
	"usuarios | usuarios | 10.1.0.0/16 | 10",
	"servicios | servicios | 10.2.0.0/16 | 20",
	"administración | administración | 10.9.0.0/24 | ",
	"wifi | inalámbrico | 10.40.0.0/16 | 40",
	"no es un rango | servicios | 10.2 | ",
})

func TestSegments(t *testing.T) {

	if len(segments) != 4 || segments[2].Purpose != Admin || segments[3].Purpose != Wireless {
		t.Fatalf("segments: %+v", segments)
	}
	web := &source.Network{Addresses: []string{"127.0.0.1", "10.2.0.5"}, ByInterface: map[string][]string{"eth0": {"10.2.0.5"}}, Interfaces: []source.Interface{{Name: "eth0", Type: "ethernet", State: "up"}}}
	check(t, "in segment", JudgeEV01(segments, web), verdict.Compliant, "", "servicios")
	check(t, "outside", JudgeEV01(segments, &source.Network{Addresses: []string{"172.16.0.4"}}), verdict.NonCompliant, "", "172.16.0.4")

	bridge := &source.Network{Addresses: []string{"10.2.0.5", "10.9.0.5"}}
	check(t, "bridge", JudgeEV03(segments, bridge, "web01", nil), verdict.NonCompliant, "", "administración")
	check(t, "declared point", JudgeEV03(segments, bridge, "web01", []string{"IC-1 | servicios ↔ administración | web01 | web01"}), verdict.Compliant, "", "")

	laptop := &source.Network{Interfaces: []source.Interface{{Name: "wlp2s0", Type: "wireless", State: "up"}}, ByInterface: map[string][]string{"wlp2s0": {"10.1.3.4"}}}
	check(t, "wireless mixed", JudgeEV04(segments, laptop), verdict.NonCompliant, "", "wlp2s0")
	laptop.ByInterface["wlp2s0"] = []string{"10.40.3.4"}
	check(t, "wireless apart", JudgeEV04(segments, laptop), verdict.Compliant, "", "1")
}

func TestFlows(t *testing.T) {
	matrix := []string{"usuarios | servicios | tcp | 443"}
	flows := []source.Flow{
		{Source: "10.1.0.7", Destination: "10.2.0.5", Protocol: "tcp", Port: "443", Count: 5},
		{Source: "10.1.0.7", Destination: "10.9.0.5", Protocol: "tcp", Port: "22", Count: 1},
		{Source: "10.2.0.5", Destination: "10.2.0.6", Protocol: "tcp", Port: "5432", Count: 9},
	}
	check(t, "leak", JudgeEV02(flows, segments, matrix), verdict.NonCompliant, "", "usuarios → administración")
	check(t, "allowed", JudgeEV02(append(flows[:1], flows[2]), segments, matrix), verdict.Compliant, "", "5")
}

func TestModality(t *testing.T) {
	if Modality("Medios físicos separados") != Physical || Modality("VLAN") != VLAN || Modality("R2") != VPN {
		t.Error("modality")
	}
	check(t, "untagged", JudgeEV07(VLAN, segments, nil), verdict.NonCompliant, "", "administración")
	check(t, "tunnel", JudgeEV07(VPN, segments, &source.Network{Interfaces: []source.Interface{{Name: "wg0", State: "up"}}}), verdict.Compliant, "", "")
	check(t, "purposes", JudgeEV08(segments), verdict.Compliant, "", "")
	check(t, "purposes missing", JudgeEV08(segments[:1]), verdict.NonCompliant, "", "servicios")
}

func TestIncidents(t *testing.T) {
	incidents := opexp7.ParseRegister([]string{"INC-1 | inicial | 2026-10-20 10:00 | alta | web01, pc01 | | | | | | | | INC-1 | "})
	where := map[string][]string{"web01": {"servicios"}, "pc01": {"usuarios"}}
	check(t, "spread", JudgeEV09(incidents, func(m string) []string { return where[m] }), verdict.NonCompliant, "", "INC-1")
	where["pc01"] = []string{"servicios"}
	check(t, "contained", JudgeEV09(incidents, func(m string) []string { return where[m] }), verdict.Compliant, "", "1")
}

package mpcom1

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
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

func TestMatching(t *testing.T) {
	cases := []struct {
		got, want bool
	}{
		{Match("10.0.0.0/8", "10.1.2.3"), true},
		{Match("10.0.0.0/8", "192.168.1.1"), false},
		{Match("*", "8.8.8.8"), true},
		{Match("192.168.1.10", "192.168.1.10"), true},
		{MatchPort("1000-2000", "1500"), true},
		{MatchPort("443", "80"), false},
		{Public("8.8.8.8"), true},
		{Public("10.0.0.1"), false},
		{Public("100.64.1.1"), false},
		{Expected("ens18", []string{"lo", "ens*"}), true},
		{Expected("wlan0", []string{"lo", "ens*"}), false},
		{Permissive("any | 10.0.0.0/8 | tcp | 22 | RSI | 2026-01-01"), true},
		{Permissive("0.0.0.0/0 | 10.0.0.5 | tcp | 443 | RSI | 2026-01-01"), false},
		{Permissive("* | 10.0.0.5 | * | * | RSI | 2026-01-01"), true},
	}
	for i, c := range cases {
		if c.got != c.want {
			t.Errorf("case %d: got %v", i, c.got)
		}
	}
}

func TestPerimeter(t *testing.T) {

	elements := []Element{
		{Name: "fw01", Source: "fw01", Hours: []time.Time{now.Add(-2 * time.Hour), now.Add(-time.Hour)}},
		{Name: "vpn01", Source: "vpn01"},
	}
	check(t, "silent", JudgeEV01(elements, 4, now), verdict.NonCompliant, "", "vpn01")
	check(t, "logging", JudgeEV01(elements[:1], 4, now), verdict.Compliant, "", "fw01")
	check(t, "gap", JudgeEV08(elements[:1], 4, now.Add(-24*time.Hour), now), verdict.NonCompliant, "", "fw01")
	check(t, "no elements", JudgeEV01(nil, 4, now), verdict.NotEvaluable, verdict.CauseConfiguration, "")

	rows := []string{"* | 192.168.10.0/24 | tcp | 443 | RSI | 2026-01-01", "192.168.10.0/24 | 10.0.0.5 | tcp | 3306 | RSI | 2026-01-01"}
	flows := []source.Flow{{Source: "203.0.113.7", Destination: "192.168.10.4", Protocol: "TCP", Port: "443", Count: 10}, {Source: "192.168.10.4", Destination: "10.0.0.6", Protocol: "tcp", Port: "3306", Count: 1}}
	check(t, "unauthorised", JudgeEV02(flows, rows), verdict.NonCompliant, "", "10.0.0.6")
	check(t, "authorised", JudgeEV02(flows[:1], rows), verdict.Compliant, "", "10")

	reviews := []string{"2026-09-01 | fw01 | RSI | ninguno"}
	check(t, "reviewed", JudgeEV06(rows, reviews, catalog.Message{}, 180, catalog.Message{}, now), verdict.Compliant, "", "")
	check(t, "permissive", JudgeEV06(append(rows, "any | 10.0.0.0/8 | tcp | 3389 | RSI | 2026-01-01"), reviews, catalog.Message{}, 180, catalog.Message{}, now), verdict.NonCompliant, "", "3389")
}

func TestMachine(t *testing.T) {

	network := &source.Network{
		Interfaces: []source.Interface{{Name: "lo", Type: "loopback", State: "up"}, {Name: "ens18", Type: "ethernet", State: "up"}, {Name: "wg0", Type: "unknown", State: "up"}, {Name: "wlan0", Type: "wireless", State: "down"}},
		Gateways:   []string{"192.168.1.1", "10.9.0.1"},
		Tunnels:    []string{"ngrok"},
	}
	check(t, "unexpected", JudgeEV03(network, []string{"lo", "ens*"}), verdict.NonCompliant, "", "wg0")
	check(t, "expected", JudgeEV03(network, []string{"lo", "ens*", "wg*"}), verdict.Compliant, "", "")
	check(t, "no inventory", JudgeEV03(nil, nil), verdict.NotEvaluable, verdict.CauseCollection, "")

	check(t, "other gateway", JudgeEV04(network, []string{"principal | fw01 | 192.168.1.1"}), verdict.NonCompliant, "", "10.9.0.1")
	check(t, "tunnels", JudgeEV05(network, []string{"wg0"}), verdict.NonCompliant, "", "ngrok")
	check(t, "tunnels allowed", JudgeEV05(network, []string{"wg0", "ngrok"}), verdict.Compliant, "", "")

	logins := []source.RemoteLogin{{Address: "192.168.1.20", Count: 3}, {Address: "198.51.100.9", Count: 40}}
	check(t, "exposed", JudgeEV07(logins, nil), verdict.NonCompliant, "", "198.51.100.9")
	check(t, "allowed", JudgeEV07(logins, []string{"198.51.100.0/24"}), verdict.Compliant, "", "")
}

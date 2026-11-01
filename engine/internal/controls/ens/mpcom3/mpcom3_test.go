package mpcom3

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
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

func settings(entries ...fact.ConfigEntry) opacc6.Settings {
	return opacc6.Settings{
		Snapshot: &fact.ConfigSnapshot{RecordsEmitted: 1},
		Files:    []fact.ConfigFile{{Source: sshClient, Status: fact.SourceRead, Entries: entries}},
	}
}

func TestPeers(t *testing.T) {
	check(t, "verified", JudgeEV01(settings(fact.ConfigEntry{Key: "Host", Value: "*", Line: 1})), verdict.Compliant, "", "")
	check(t, "unverified", JudgeEV01(settings(fact.ConfigEntry{Key: "StrictHostKeyChecking", Value: "no", Line: 7})), verdict.NonCompliant, "", ":7")
	check(t, "known hosts thrown away", JudgeEV01(settings(fact.ConfigEntry{Key: "UserKnownHostsFile", Value: "/dev/null", Line: 9})), verdict.NonCompliant, "", "/dev/null")
}

func TestAttacks(t *testing.T) {

	m := &source.Manager{Rules: []source.Rule{{ID: 100200, Level: 10}, {ID: 100201, Level: 0}}}
	rows := []string{"alteración | MAC inválido en el VPN | strongSwan | 100200", "secuestro | sesión desde dos IP | proxy | 100201"}
	check(t, "detected", JudgeAttack(m, rows, "alteracion"), verdict.Compliant, "", "MAC")
	check(t, "blind", JudgeAttack(m, rows, "secuestro"), verdict.NonCompliant, "", "sesión")
	check(t, "undeclared", JudgeAttack(m, rows, "inyeccion"), verdict.NonCompliant, "", "inyeccion")
	if ids := RuleIDs(m, rows); len(ids) != 1 || ids[0] != "100200" {
		t.Errorf("rule ids: %v", ids)
	}

	incidents := opexp7.Of(opexp7.ParseRegister([]string{"INC-9 | inicial | 2026-11-01 08:30 | alta | web01 | | | | | | | | INC-9 | "}), "web01", now)
	hours := []time.Time{time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC), time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)}
	check(t, "unhandled", JudgeEV07(hours, incidents), verdict.NonCompliant, "", "2026-10-30 03:00")
	check(t, "handled", JudgeEV07(hours[:1], incidents), verdict.Compliant, "", "1")
}

func TestChannels(t *testing.T) {

	network := &source.Network{Interfaces: []source.Interface{{Name: "wg0", State: "up"}}}
	rows := []string{"sede remota | web01 | wg0 | WireGuard | ChaCha20", "AEAT | web01 | ipsec0 | IPsec | AES-256", "otra | db01 | tun0 | | "}
	check(t, "down", JudgeEV08(rows, "web01", network), verdict.NonCompliant, "", "AEAT")
	check(t, "up", JudgeEV08(rows[:1], "web01", network), verdict.Compliant, "", "1")
	check(t, "no channels", JudgeEV08(rows, "app01", network), verdict.Compliant, "", "")

	fim := []source.FIMChange{{Time: now.Add(-time.Hour), Path: "/etc/ipsec.conf", Event: "modified"}, {Time: now.Add(-time.Hour), Path: "/etc/hosts", Event: "modified"}}
	check(t, "unrequested", JudgeEV10(fim, []string{"/etc/ipsec.conf"}, nil, "web01", now.Add(-24*time.Hour)), verdict.NonCompliant, "", "ipsec.conf")
	requests := opexp5.ParseRegister([]string{"RFC-1 | 2026-10-30 | web01 | cambio de VPN | bajo | RSI | 2026-10-31 | 2026-11-01 00:00 | 2026-11-01 23:59 | aprobada | | "})
	check(t, "requested", JudgeEV10(fim, []string{"/etc/ipsec.conf"}, requests, "web01", now.Add(-24*time.Hour)), verdict.Compliant, "", "1")

	check(t, "certified", JudgeEV11([]string{"cifrador | CC EAL4+ | CCN-1 | 2028-06-30"}, now), verdict.Compliant, "", "")
	check(t, "expired", JudgeEV11([]string{"cifrador | CC EAL4+ | CCN-1 | 2026-06-30"}, now), verdict.NonCompliant, "", "cifrador")
}

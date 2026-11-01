package mpeq3

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

func TestInventory(t *testing.T) {
	inventory := []string{"PRT-014 | portátil | J. Gómez | MEDIO", "PRT-015 | portátil | | BAJO"}
	e, ok := Entry(inventory, "prt-014")
	check(t, "inventoried", JudgeEV01(e, ok), verdict.Compliant, "", "J. Gómez")
	e, ok = Entry(inventory, "PRT-015")
	check(t, "no responsible", JudgeEV01(e, ok), verdict.NonCompliant, "", "")
	e, ok = Entry(inventory, "PRT-099")
	check(t, "missing", JudgeEV01(e, ok), verdict.NonCompliant, "", "")
}

func TestCustody(t *testing.T) {
	alive := &source.Reporting{LastKeepAlive: now.Add(-time.Hour)}
	checks := []string{"2026-10-01 | PRT-014 | J. Gómez | en su poder", "2026-10-30 | PRT-099 | X | en su poder"}
	check(t, "checked", JudgeEV02(alive, checks, "PRT-014", 90, now), verdict.Compliant, "", "")
	check(t, "overdue", JudgeEV02(alive, checks, "PRT-014", 20, now), verdict.NonCompliant, "", "")
	check(t, "silent", JudgeEV02(nil, checks, "PRT-014", 90, now), verdict.NonCompliant, "", "")
}

func TestKeysAndDisk(t *testing.T) {
	snapshot := &fact.KeySnapshot{Status: fact.SourceRead}
	keys := []fact.KeyRecord{{Path: "/home/jgomez/.ssh/id_ed25519"}, {Path: "/etc/ssh/ssh_host_ed25519_key"}}
	check(t, "remote keys", JudgeEV03(snapshot, keys, nil), verdict.NonCompliant, "", "id_ed25519")
	check(t, "allowed", JudgeEV03(snapshot, keys, []string{"/home/*/.ssh/id_ed25519"}), verdict.Compliant, "", "")
	check(t, "no snapshot", JudgeEV03(nil, nil, nil), verdict.NotEvaluable, verdict.CauseCollection, "")

	check(t, "encrypted", JudgeEV04(&fact.DeviceSecurity{Status: fact.SourceRead, RootEncrypted: true, RootDevice: "dm-1"}, "MEDIO"), verdict.Compliant, "", "dm-1")
	check(t, "plain", JudgeEV04(&fact.DeviceSecurity{Status: fact.SourceRead, RootDevice: "sda2"}, "ALTO"), verdict.NonCompliant, "", "sda2")
	check(t, "low", JudgeEV04(nil, "BAJO"), verdict.Compliant, "", "")
}

func TestLosses(t *testing.T) {
	losses := []string{"2026-10-01T10:00:00Z | PRT-014 | INC-7 | 2026-10-01T11:30:00Z", "2026-10-05T10:00:00Z | PRT-014 | | 2026-10-05T10:30:00Z"}
	check(t, "unhandled", JudgeEV06(losses, "PRT-014", 4), verdict.NonCompliant, "", "2026-10-05")
	check(t, "handled", JudgeEV06(losses[:1], "PRT-014", 4), verdict.Compliant, "", "1")
}

package mpeq2

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func n(v int) *int { return &v }

func b(v bool) *bool { return &v }

func TestLock(t *testing.T) {

	desktop := &fact.DeviceSecurity{Status: fact.SourceRead, Graphical: true, IdleDelay: n(600), LockEnabled: b(true), LockDelay: n(0), LogindIdle: 3600}
	check(t, "locked", JudgeEV01(desktop, 15), verdict.Compliant, "", "600")
	check(t, "late", JudgeEV01(desktop, 5), verdict.NonCompliant, "", "600")
	desktop.LockEnabled = b(false)
	check(t, "disabled", JudgeEV01(desktop, 15), verdict.NonCompliant, "", "")
	desktop.LockEnabled, desktop.IdleDelay = b(true), n(0)
	check(t, "never idle", JudgeEV01(desktop, 15), verdict.NonCompliant, "", "")

	console := &fact.DeviceSecurity{Status: fact.SourceRead, ShellTimeout: 600, ShellReadonly: true}
	check(t, "shell", JudgeEV01(console, 15), verdict.Compliant, "", "600")
	console.ShellReadonly = false
	check(t, "writable", JudgeEV01(console, 15), verdict.NonCompliant, "", "")
	check(t, "no fact", JudgeEV01(nil, 15), verdict.NotEvaluable, verdict.CauseCollection, "")
}

func TestCancel(t *testing.T) {
	d := &fact.DeviceSecurity{Status: fact.SourceRead, Graphical: true, LogindIdle: 3600}
	check(t, "cancelled", JudgeEV02(d, 15, 60), verdict.Compliant, "", "3600")
	check(t, "late", JudgeEV02(d, 15, 30), verdict.NonCompliant, "", "")
	check(t, "before lock", JudgeEV02(d, 60, 120), verdict.NonCompliant, "", "")
	check(t, "none", JudgeEV02(&fact.DeviceSecurity{Status: fact.SourceRead, Graphical: true}, 15, 60), verdict.NonCompliant, "", "")
}

func TestInhibitors(t *testing.T) {
	check(t, "found", JudgeEV05([]string{"bash", "Caffeine"}, Inhibitors), verdict.NonCompliant, "", "Caffeine")
	check(t, "none", JudgeEV05([]string{"bash"}, Inhibitors), verdict.Compliant, "", "")
}

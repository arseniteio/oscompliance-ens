// Package mpeq2 judges mp.eq.2, locking the workstation: the screen or shell locked after the idle time of
// P-01, sessions cancelled after the longer time of P-02, and no tool that keeps the session awake.
package mpeq2

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Inhibitors are the process names of tools that keep a session from going idle.
var Inhibitors = []string{"caffeine", "caffeine-ng", "caffeinate", "jiggler", "mousejiggler", "keepawake", "nosleep", "insomnia", "stay-awake"}

func gap(d *fact.DeviceSecurity) (verdict.Judgement, bool) {
	switch {
	case d == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.DeviceSecurityFact)), true
	case d.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("device", d.Status, d.Error)), true
	}
	return verdict.Judgement{}, false
}

// JudgeEV01 needs the session locked within the minutes of P-01: the screen lock of the graphical session,
// or a shell timeout users cannot undo on a machine without one.
func JudgeEV01(d *fact.DeviceSecurity, minutes int) verdict.Judgement {

	if j, ok := gap(d); ok {
		return j
	}
	limit := minutes * 60

	if d.Graphical {
		switch {
		case d.LockEnabled == nil || !*d.LockEnabled:
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.lock_disabled"))
		case d.IdleDelay == nil || *d.IdleDelay == 0:
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.never_idle"))
		}
		total := *d.IdleDelay
		if d.LockDelay != nil {
			total += *d.LockDelay
		}
		if total > limit {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.lock_late", "seconds", total, "max", limit))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq2.lock", "seconds", total, "max", limit))
	}

	switch {
	case d.ShellTimeout == 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.no_shell_timeout"))
	case !d.ShellReadonly:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.shell_timeout_writable", "seconds", d.ShellTimeout))
	case d.ShellTimeout > limit:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.lock_late", "seconds", d.ShellTimeout, "max", limit))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq2.shell_timeout", "seconds", d.ShellTimeout, "max", limit))
}

// JudgeEV02 needs idle sessions cancelled after more than the minutes of P-01 and at most those of P-02:
// logind's StopIdleSessionSec, or the shell timeout of a machine without a graphical session.
func JudgeEV02(d *fact.DeviceSecurity, lockMinutes, cancelMinutes int) verdict.Judgement {

	if j, ok := gap(d); ok {
		return j
	}
	seconds := d.LogindIdle
	if seconds == 0 && !d.Graphical {
		seconds = d.ShellTimeout
	}
	switch {
	case seconds == 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.no_cancel"))
	case seconds <= lockMinutes*60:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.cancel_before_lock", "seconds", seconds, "lock", lockMinutes*60))
	case seconds > cancelMinutes*60:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.cancel_late", "seconds", seconds, "max", cancelMinutes*60))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq2.cancel", "seconds", seconds, "max", cancelMinutes*60))
}

// JudgeEV05 needs none of the inhibitors running.
func JudgeEV05(running, inhibitors []string) verdict.Judgement {
	var found []string
	for _, p := range running {
		if slices.ContainsFunc(inhibitors, func(i string) bool { return strings.EqualFold(i, p) }) && !slices.Contains(found, p) {
			found = append(found, p)
		}
	}
	if len(found) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq2.inhibitors", "list", found))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq2.no_inhibitors", "count", len(inhibitors)))
}

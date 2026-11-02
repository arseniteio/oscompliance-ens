package mpeq2

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

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

// Package mpeq3 judges mp.eq.3, portable devices: each one inventoried with its responsible and its custody
// checked, losses handled, no dispensable remote access keys on it and, at ALTO, its disk encrypted.
package mpeq3

import (
	"path"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

// Entry is the row of P-01 (`dispositivo | tipo | responsable | nivel_confidencialidad`) of a machine.
func Entry(rows []string, machine string) ([]string, bool) {
	for _, r := range rows {
		if c := cells(r, 4); strings.EqualFold(c[0], machine) {
			return c, true
		}
	}
	return nil, false
}

// JudgeEV01 needs the portable machine in the inventory of P-01 with its responsible.
func JudgeEV01(entry []string, inventoried bool) verdict.Judgement {
	switch {
	case !inventoried:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.not_inventoried"))
	case entry[2] == "":
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.no_responsible"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq3.inventoried", "responsible", entry[2]))
}

// JudgeEV02 needs the device reporting and its custody checked in P-09 (`fecha | dispositivo | responsable |
// resultado`) within the days of P-02.
func JudgeEV02(reporting *source.Reporting, checks []string, machine string, days int, now time.Time) verdict.Judgement {

	if reporting == nil || reporting.LastKeepAlive.IsZero() || now.Sub(reporting.LastKeepAlive) > time.Duration(days)*24*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.silent", "days", days))
	}
	var mine []string
	for _, r := range checks {
		if strings.EqualFold(cells(r, 2)[1], machine) {
			mine = append(mine, r)
		}
	}
	j, _ := passes.Review(mine, catalog.Message{}, "P-09", days, catalog.Message{}, "P-02", now)
	return j
}

// JudgeEV03 needs no private key in the users' homes outside the paths of P-05.
func JudgeEV03(snapshot *fact.KeySnapshot, keys []fact.KeyRecord, allowed []string) verdict.Judgement {

	switch {
	case snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.KeySnapshotFact))
	case snapshot.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("keys", snapshot.Status, snapshot.Error))
	}
	var found []string
	for _, k := range keys {
		home := strings.HasPrefix(k.Path, "/home/") || strings.HasPrefix(k.Path, "/root/")
		if home && !slices.ContainsFunc(allowed, func(p string) bool { ok, _ := path.Match(p, k.Path); return ok || p == k.Path }) {
			found = append(found, k.Path)
		}
	}
	if len(found) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.remote_keys", "list", found))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq3.no_remote_keys"))
}

// Confidential tells whether the level of P-01 asks for an encrypted disk: MEDIO or above.
func Confidential(level string) bool {
	l := strings.ToUpper(strings.TrimSpace(level))
	return l == "MEDIO" || l == "ALTO"
}

// JudgeEV04 needs the root filesystem encrypted when the device holds information of MEDIO or above.
func JudgeEV04(d *fact.DeviceSecurity, level string) verdict.Judgement {
	switch {
	case !Confidential(level):
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq3.encryption_not_required", "level", level))
	case d == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.DeviceSecurityFact))
	case d.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("device", d.Status, d.Error))
	case !d.RootEncrypted:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.not_encrypted", "device", d.RootDevice, "level", level))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq3.encrypted", "device", d.RootDevice))
}

// JudgeEV06 needs every loss of the device in P-10 (`fecha | dispositivo | incidente | acciones_completadas`)
// with its incident and its actions completed within the hours of P-08.
func JudgeEV06(losses []string, machine string, hours int) verdict.Judgement {
	var late []string
	count := 0
	for _, r := range losses {
		c := cells(r, 4)
		if !strings.EqualFold(c[1], machine) {
			continue
		}
		count++
		lost, okLost := opcont2.Date(c[0])
		done, okDone := opcont2.Date(c[3])
		if c[2] == "" || !okLost || !okDone || done.Sub(lost) > time.Duration(hours)*time.Hour {
			late = append(late, c[0])
		}
	}
	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq3.losses_unhandled", "hours", hours, "list", late))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq3.losses_handled", "count", count))
}

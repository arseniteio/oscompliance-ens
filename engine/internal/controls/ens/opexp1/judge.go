package opexp1

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Freshness struct {
	Config       *fact.WazuhAgentConfig
	Reporting    *source.Reporting
	Manager      bool
	MaxHours     int
	HoursProblem catalog.Message
	Now          time.Time
}

func (f Freshness) Stale(scans []string) (verdict.Judgement, bool) {

	if !f.HoursProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, f.HoursProblem), true
	}

	c := f.Config
	if c == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact)), true
	}
	if c.Status != fact.SourceRead {
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", c.Status, c.Error)), true
	}
	if c.SyscollectorDisabled {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.syscollector_disabled")), true
	}

	var off []string
	for _, s := range scans {
		if !slices.Contains(c.SyscollectorScans, s) {
			off = append(off, s)
		}
	}
	if len(off) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.scans_off", "scans", off)), true
	}

	if c.SyscollectorInterval > f.MaxHours*3600 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.interval_too_long", "interval", hours(c.SyscollectorInterval), "max", f.MaxHours)), true
	}

	if f.Manager {
		return verdict.Judgement{}, false
	}
	if f.Reporting == nil || f.Reporting.LastKeepAlive.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_monitoring")), true
	}
	if age := f.Now.Sub(f.Reporting.LastKeepAlive); age > time.Duration(f.MaxHours)*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.no_contact", "since", stamp(f.Reporting.LastKeepAlive), "max", f.MaxHours)), true
	}

	return verdict.Judgement{}, false
}

func hours(seconds int) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", float64(seconds)/3600), "0"), ".")
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func missing(kind string) verdict.Judgement {
	return passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_inventory", "kind", catalog.Says(kind)))
}

func JudgeEV01(inv *source.Inventory, f Freshness) verdict.Judgement {

	if j, stale := f.Stale([]string{"os", "hardware"}); stale {
		return j
	}
	if inv == nil || inv.System == nil {
		return missing("opexp1.kind_system")
	}
	if inv.Hardware == nil {
		return missing("opexp1.kind_hardware")
	}

	s, h := inv.System, inv.Hardware
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.system",
		"os", strings.TrimSpace(s.OS+" "+s.Version), "kernel", s.Kernel, "arch", s.Architecture, "cores", h.Cores, "memory", h.MemoryMB))
}

func JudgeEV02(inv *source.Inventory, f Freshness) verdict.Judgement {

	if j, stale := f.Stale([]string{"packages"}); stale {
		return j
	}
	if inv == nil || len(inv.Packages) == 0 {
		return missing("opexp1.kind_packages")
	}

	types := make([]string, 0, len(inv.Packages))
	total := 0
	for t, n := range inv.Packages {
		if t == "" {
			t = "?"
		}
		types = append(types, fmt.Sprintf("%s %d", t, n))
		total += n
	}
	slices.Sort(types)

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.packages", "count", total, "types", types))
}

func JudgeEV03(inv *source.Inventory, f Freshness) verdict.Judgement {

	if j, stale := f.Stale([]string{"network", "ports", "processes"}); stale {
		return j
	}
	if inv == nil || len(inv.Addresses) == 0 {
		return missing("opexp1.kind_networks")
	}
	if inv.Processes == 0 {
		return missing("opexp1.kind_processes")
	}

	addresses := slices.Clone(inv.Addresses)
	slices.Sort(addresses)
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.network", "addresses", addresses, "ports", inv.Listening, "processes", inv.Processes))
}

func JudgeEV04(r *source.Reporting, manager bool, maxHours int, hoursProblem catalog.Message, now time.Time) verdict.Judgement {

	if manager {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.manager_reporting"))
	}
	if !hoursProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, hoursProblem)
	}
	if r == nil || r.LastKeepAlive.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_monitoring"))
	}

	if r.Status != "active" {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.agent_status", "status", r.Status, "since", stamp(r.LastKeepAlive)))
	}
	if now.Sub(r.LastKeepAlive) > time.Duration(maxHours)*time.Hour {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.no_contact", "since", stamp(r.LastKeepAlive), "max", maxHours))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.reporting", "since", stamp(r.LastKeepAlive)))
}

func JudgeEV05(s *fact.NeighbourSnapshot, declared []string, declaredProblem catalog.Message, agents map[string]bool) verdict.Judgement {

	if s == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.NeighbourSnapshotFact))
	}
	if s.Status != fact.SourceRead {
		return passes.Gap(verdict.CauseCollection, passes.Source("/proc/net/arp", s.Status, s.Error))
	}
	if !declaredProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, declaredProblem)
	}

	known := map[string]bool{}
	for _, ip := range declared {
		if ip = strings.TrimSpace(ip); ip != "" {
			known[ip] = true
		}
	}

	var unknown []string
	for _, n := range s.Neighbours {
		if !known[n.IP] && !agents[n.IP] {
			unknown = append(unknown, n.IP+" ("+n.MAC+")")
		}
	}

	if len(unknown) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.unknown_neighbours", "list", unknown))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.neighbours_known", "count", len(s.Neighbours)))
}

func JudgeEV06(rows []string, rowsProblem catalog.Message, maxDays int, daysProblem catalog.Message, changes map[time.Time]int, now time.Time) verdict.Judgement {

	j, last := passes.Review(rows, rowsProblem, ReviewParam, maxDays, daysProblem, "P-04", now)
	if last.IsZero() {
		return j
	}

	n := 0
	for day, count := range changes {
		if !day.Before(last.Truncate(24 * time.Hour)) {
			n += count
		}
	}
	return verdict.Explain(j.Status, j.Cause, catalog.Says("opexp1.review_changes", "review", j.Message, "changes", n))
}

const ReviewParam = "P-09"

func JudgeEV07(name string, rows []string, rowsProblem catalog.Message, natures []string, naturesProblem catalog.Message) verdict.Judgement {

	if !rowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, rowsProblem)
	}
	if !naturesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, naturesProblem)
	}

	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 4 {
			c = append(c, "")
		}
		asset, owner, nature := strings.TrimSpace(c[0]), strings.TrimSpace(c[1]), strings.TrimSpace(c[3])
		if !strings.EqualFold(asset, name) {
			continue
		}

		switch {
		case owner == "":
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.no_owner", "asset", asset))
		case nature == "":
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.no_nature", "asset", asset))
		case len(natures) > 0 && !slices.ContainsFunc(natures, func(n string) bool { return strings.EqualFold(strings.TrimSpace(n), nature) }):
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.nature_not_in_p_03", "asset", asset, "nature", nature))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp1.declared", "asset", asset, "owner", owner, "nature", nature))
	}

	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp1.not_declared", "asset", name))
}

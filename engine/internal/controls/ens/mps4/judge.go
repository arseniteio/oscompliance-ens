package mps4

import (
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

func gap(d *fact.DeviceSecurity) (verdict.Judgement, bool) {
	switch {
	case d == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.DeviceSecurityFact)), true
	case d.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("device", d.Status, d.Error)), true
	}
	return verdict.Judgement{}, false
}

func JudgeEV01(d *fact.DeviceSecurity, max int) verdict.Judgement {
	if j, ok := gap(d); ok {
		return j
	}
	if d.LoadPercent > max || d.MemoryPercent > max {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.no_headroom", "load", d.LoadPercent, "memory", d.MemoryPercent, "max", max))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.headroom", "load", d.LoadPercent, "memory", d.MemoryPercent, "max", max))
}

func JudgeEV02(d *fact.DeviceSecurity, fw *fact.FirewallSnapshot) verdict.Judgement {
	if j, ok := gap(d); ok {
		return j
	}
	var missing []string
	if !d.SynCookies {
		missing = append(missing, "syncookies")
	}
	switch {
	case fw == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.FirewallSnapshotFact))
	case fw.Status != fact.SourceRead || !slices.ContainsFunc(fw.Chains, func(c fact.FirewallChain) bool { return c.Hook == "input" && c.Policy == "drop" }):
		missing = append(missing, "firewall")
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.prevention_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.prevention"))
}

func JudgeEV07(m *source.Manager, rules []string) verdict.Judgement {
	for _, r := range m.Responses {
		if r.Disabled {
			continue
		}
		for _, id := range strings.Split(r.Rules, ",") {
			if slices.Contains(rules, strings.TrimSpace(id)) {
				return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.containment", "command", r.Command, "rule", strings.TrimSpace(id)))
			}
		}
	}
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.no_containment"))
}

func DoSRules(m *source.Manager, rows []string) []string {
	var out []string
	for _, r := range rows {
		ranges, err := opmon1.ParseRules(cells(r, 4)[3])
		if err != nil {
			continue
		}
		for _, rule := range opmon1.Alerting(m.Rules, ranges) {
			out = append(out, strconv.Itoa(rule.ID))
		}
	}
	return out
}

func JudgeEV06(episodes []string) verdict.Judgement {
	var untold []string
	high := 0
	for _, r := range episodes {
		c := cells(r, 7)
		if opcont2.Person(c[4]) != "alto" {
			continue
		}
		high++
		if c[6] == "" {
			untold = append(untold, c[0]+" "+c[2])
		}
	}
	if len(untold) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.provider_untold", "list", untold))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.provider_told", "count", high))
}

func JudgeEV10(episodes []string) verdict.Judgement {
	var incomplete []string
	for _, r := range episodes {
		if c := cells(r, 7); c[3] == "" || c[4] == "" || c[5] == "" {
			incomplete = append(incomplete, c[0]+" "+c[2])
		}
	}
	if len(incomplete) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.episodes_incomplete", "list", incomplete))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.episodes", "count", len(episodes)))
}

var Amplifiers = map[int]string{19: "chargen", 53: "dns", 123: "ntp", 161: "snmp", 389: "cldap", 1900: "ssdp", 5353: "mdns", 11211: "memcached"}

func JudgeEV09(sockets []fact.ListeningSocket, allowed []string) verdict.Judgement {
	var open []string
	for _, s := range sockets {
		name, amplifies := Amplifiers[s.Port]
		if s.Protocol != "udp" || !amplifies || s.Address == "127.0.0.1" || s.Address == "::1" || strings.HasPrefix(s.Address, "127.") {
			continue
		}
		if slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, name) || a == strconv.Itoa(s.Port) }) {
			continue
		}
		open = append(open, name+" "+s.Address+":"+strconv.Itoa(s.Port))
	}
	if len(open) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.amplifiers", "list", open))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.no_amplifiers"))
}

// Package mps4 judges mp.s.4, protection against denial of service, on the machines of the exposed
// services: headroom of CPU and memory, prevention on the machine, detection and automatic containment
// backed by Wazuh, the register of episodes with their reaction, and services that can amplify attacks.
package mps4

import (
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
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

// JudgeEV01 needs CPU and memory in use at most the percentage of P-02, the headroom the requirement asks.
func JudgeEV01(d *fact.DeviceSecurity, max int) verdict.Judgement {
	if j, ok := gap(d); ok {
		return j
	}
	if d.LoadPercent > max || d.MemoryPercent > max {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps4.no_headroom", "load", d.LoadPercent, "memory", d.MemoryPercent, "max", max))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps4.headroom", "load", d.LoadPercent, "memory", d.MemoryPercent, "max", max))
}

// JudgeEV02 needs SYN cookies on and a firewall that drops by default what reaches the machine.
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

// JudgeEV07 needs an active response of the manager triggered by a rule of the denial of service
// indicators.
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

// DoSRules are the loaded rules P-03 names for denial of service.
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

// JudgeEV06 needs every episode of P-07 (`inicio | fin | servicio | vector | impacto | respuesta |
// proveedor`) of high impact with the provider told.
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

// JudgeEV10 needs every episode of P-07 with its vector, impact and response.
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

// Amplifiers are the UDP ports of services that answer small queries with large replies.
var Amplifiers = map[int]string{19: "chargen", 53: "dns", 123: "ntp", 161: "snmp", 389: "cldap", 1900: "ssdp", 5353: "mdns", 11211: "memcached"}

// JudgeEV09 needs no UDP service that can amplify attacks open beyond loopback, outside P-08.
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

package mpcom1

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

type Element struct {
	Name, Source string
	Hours        []time.Time
}

func Sources(rows []string) []Element {
	var out []Element
	for _, r := range rows {
		c := cells(r, 4)
		if c[3] != "" {
			out = append(out, Element{Name: c[0], Source: c[3]})
		}
	}
	return out
}

func JudgeEV01(elements []Element, maxHours int, now time.Time) verdict.Judgement {

	if len(elements) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("mpcom1.no_elements"))
	}
	var silent, logging []catalog.Message
	for _, e := range elements {
		var last time.Time
		if len(e.Hours) > 0 {
			last = slices.MaxFunc(e.Hours, func(a, b time.Time) int { return a.Compare(b) })
		}
		if last.IsZero() || now.Sub(last) > time.Duration(maxHours+1)*time.Hour {
			silent = append(silent, catalog.Says("item.name_detail", "name", e.Name, "detail", e.Source))
		} else {
			logging = append(logging, catalog.Says("mpinfo6.item_date", "name", e.Name, "date", day(last)))
		}
	}
	if len(silent) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.elements_silent", "hours", maxHours, "list", silent))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.elements_logging", "list", logging))
}

func JudgeEV08(elements []Element, maxHours int, since, now time.Time) verdict.Judgement {

	var gapped []catalog.Message
	for _, e := range elements {
		hours := slices.Clone(e.Hours)
		slices.SortFunc(hours, func(a, b time.Time) int { return a.Compare(b) })
		marks := append(append([]time.Time{since}, hours...), now)
		longest := time.Duration(0)
		for i := 1; i < len(marks); i++ {
			longest = max(longest, marks[i].Sub(marks[i-1]))
		}
		if longest > time.Duration(maxHours+1)*time.Hour {
			gapped = append(gapped, catalog.Says("mpcom1.item_gap", "name", e.Name, "hours", int(longest.Hours())))
		}
	}
	if len(gapped) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.logs_gapped", "max", maxHours, "list", gapped))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.logs_continuous", "count", len(elements), "max", maxHours))
}

func Authorised(f source.Flow, rows []string) bool {
	return slices.ContainsFunc(rows, func(r string) bool {
		c := cells(r, 6)
		protocol := strings.ToLower(c[2])
		return c[4] != "" && Match(c[0], f.Source) && Match(c[1], f.Destination) &&
			(protocol == "" || protocol == "*" || protocol == "any" || strings.EqualFold(protocol, f.Protocol)) && MatchPort(c[3], f.Port)
	})
}

func JudgeEV02(flows []source.Flow, rows []string) verdict.Judgement {
	var unauthorised []string
	total := 0
	for _, f := range flows {
		total += f.Count
		if !Authorised(f, rows) {
			unauthorised = append(unauthorised, f.Source+" → "+f.Destination+" "+f.Protocol+"/"+f.Port)
		}
	}
	if len(unauthorised) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.flows_unauthorised", "list", unauthorised))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.flows_authorised", "count", total, "flows", len(flows)))
}

func JudgeEV03(network *source.Network, patterns []string) verdict.Judgement {
	if network == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("mpcom1.no_inventory"))
	}
	var unexpected []string
	for _, i := range network.Interfaces {
		if i.State == "up" && !Expected(i.Name, patterns) {
			unexpected = append(unexpected, i.Name+" ("+i.Type+")")
		}
	}
	if len(unexpected) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.interfaces_unexpected", "list", unexpected))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.interfaces_expected", "count", len(network.Interfaces)))
}

func JudgeEV04(network *source.Network, exits []string) verdict.Judgement {
	if network == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("mpcom1.no_inventory"))
	}
	var gateways []string
	for _, r := range exits {
		gateways = append(gateways, cells(r, 3)[2])
	}
	var other []string
	for _, g := range network.Gateways {
		if !slices.ContainsFunc(gateways, func(e string) bool { return e != "" && Match(e, g) }) {
			other = append(other, g)
		}
	}
	if len(other) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.gateways_other", "list", other))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.gateways_expected", "list", network.Gateways))
}

func JudgeEV05(network *source.Network, allowed []string) verdict.Judgement {
	if network == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("mpcom1.no_inventory"))
	}
	ok := func(name string) bool {
		return slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, name) })
	}
	var tunnels []string
	for _, i := range network.Interfaces {
		if i.State == "up" && Tunnel(i.Type, i.Name) && !ok(i.Name) {
			tunnels = append(tunnels, i.Name)
		}
	}
	for _, t := range network.Tunnels {
		if !ok(t) {
			tunnels = append(tunnels, t)
		}
	}
	if len(tunnels) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.tunnels", "list", tunnels))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.no_tunnels"))
}

func Permissive(row string) bool {
	c := cells(row, 4)
	if !Anywhere(c[0]) {
		return false
	}
	if MatchPort(c[3], "0") && MatchPort(c[3], "65535") {
		return true
	}
	return slices.ContainsFunc(AdminPorts, func(p int) bool { return MatchPort(c[3], strconv.Itoa(p)) })
}

func JudgeEV06(flows, reviews []string, reviewsProblem catalog.Message, days int, daysProblem catalog.Message, now time.Time) verdict.Judgement {
	var permissive []string
	for _, r := range flows {
		if Permissive(r) {
			permissive = append(permissive, strings.TrimSpace(r))
		}
	}
	if len(permissive) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.permissive", "list", permissive))
	}
	j, _ := passes.Review(reviews, reviewsProblem, "P-11", days, daysProblem, "P-04", now)
	return j
}

func JudgeEV07(logins []source.RemoteLogin, allowed []string) verdict.Judgement {
	var exposed []string
	for _, l := range logins {
		if Public(l.Address) && !slices.ContainsFunc(allowed, func(n string) bool { return Match(n, l.Address) }) {
			exposed = append(exposed, l.Address+" ×"+strconv.Itoa(l.Count))
		}
	}
	if len(exposed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom1.admin_exposed", "list", exposed))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom1.admin_internal", "count", len(logins)))
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

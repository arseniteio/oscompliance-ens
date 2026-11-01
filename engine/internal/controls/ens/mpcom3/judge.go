// Package mpcom3 judges mp.com.3, integrity and authenticity of communications: peers authenticated before
// exchanging, active attacks detected and handled as incidents, encrypted tunnels outside the domain, the
// configuration of the channels kept under change control, and certified products.
package mpcom3

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

const sshClient = "/etc/ssh/ssh_config"

// JudgeEV01 needs the SSH client to refuse peers whose host key it does not know: no StrictHostKeyChecking
// no and no known hosts thrown away.
func JudgeEV01(settings opacc6.Settings) verdict.Judgement {

	if gap, found := settings.Gap(); found {
		return gap
	}
	var lax []string
	read := false
	for _, f := range settings.Files {
		if f.Source != sshClient && !strings.HasPrefix(f.Source, sshClient+".d/") {
			continue
		}
		if f.Status == fact.SourceUnreadable || f.Status == fact.SourceError {
			return passes.Gap(verdict.CauseCollection, passes.Source(f.Source, f.Status, f.Error))
		}
		read = read || f.Status == fact.SourceRead
		for _, e := range f.Entries {
			key, value := strings.ToLower(e.Key), strings.ToLower(strings.TrimSpace(e.Value))
			if (key == "stricthostkeychecking" && (value == "no" || value == "off")) || (key == "userknownhostsfile" && value == "/dev/null") {
				lax = append(lax, f.Source+":"+strconv.Itoa(e.Line)+" "+e.Key+" "+e.Value)
			}
		}
	}
	if len(lax) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.peers_unverified", "list", lax))
	}
	if !read {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.no_ssh_client"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.peers_verified"))
}

// Attacks of mp.com.3.2 as P-02 names them.
var Attacks = []string{"alteracion", "inyeccion", "secuestro"}

// Indicator is a row of P-02 (`ataque | indicador | fuente | reglas`) and the rules it names.
type Indicator struct {
	Kind, Name, Rules string
	Ranges            []opmon1.Range
	Err               error
}

// Detection are the indicators of P-02 for one attack.
func Detection(rows []string, attack string) []Indicator {
	var out []Indicator
	for _, r := range rows {
		c := cells(r, 4)
		if strings.ReplaceAll(opcont2.Person(c[0]), " ", "_") != attack {
			continue
		}
		ranges, err := opmon1.ParseRules(c[3])
		out = append(out, Indicator{Kind: c[0], Name: c[1], Rules: c[3], Ranges: ranges, Err: err})
	}
	return out
}

// JudgeAttack needs every indicator of an attack in P-02 with a loaded rule that can alert.
func JudgeAttack(m *source.Manager, rows []string, attack string) verdict.Judgement {

	indicators := Detection(rows, attack)
	if len(indicators) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.attack_undeclared", "attack", strings.ReplaceAll(attack, "_", " ")))
	}
	// Named as the parameter writes it, accents and all.
	name := indicators[0].Kind
	var blind, covered []catalog.Message
	for _, in := range indicators {
		if in.Err != nil || len(in.Ranges) == 0 {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opmon1.bad_rules", "name", in.Name, "rules", in.Rules))
		}
		n := len(opmon1.Alerting(m.Rules, in.Ranges))
		if n == 0 {
			blind = append(blind, catalog.Says("item.name_detail", "name", in.Name, "detail", in.Rules))
		} else {
			covered = append(covered, catalog.Says("opmon1.item_rules", "name", in.Name, "count", n))
		}
	}
	if len(blind) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.attack_blind", "attack", name, "list", blind))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.attack_detected", "attack", name, "list", covered))
}

// RuleIDs are the loaded rules P-02 names for every attack.
func RuleIDs(m *source.Manager, rows []string) []string {
	var out []string
	for _, attack := range Attacks {
		for _, in := range Detection(rows, attack) {
			for _, r := range opmon1.Alerting(m.Rules, in.Ranges) {
				if id := strconv.Itoa(r.ID); !slices.Contains(out, id) {
					out = append(out, id)
				}
			}
		}
	}
	return out
}

// JudgeEV07 needs an incident of op.exp.7 for the machine opened within a day of every hour it detected an
// active attack.
func JudgeEV07(hours []time.Time, incidents []opexp7.Incident) verdict.Judgement {
	var unhandled []string
	for _, h := range hours {
		if !slices.ContainsFunc(incidents, func(in opexp7.Incident) bool {
			o := in.Opened()
			return !o.Before(h.Add(-time.Hour)) && !o.After(h.Add(24*time.Hour))
		}) {
			unhandled = append(unhandled, h.Format("2006-01-02 15:04"))
		}
	}
	if len(unhandled) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.attacks_unhandled", "list", unhandled))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.attacks_handled", "count", len(hours)))
}

// JudgeEV08 needs every channel of P-05 (`canal | sistema | tunel | protocolo | cifrado`) of the machine
// running through its tunnel: the interface up, or the tunnelling process.
func JudgeEV08(rows []string, machine string, network *source.Network) verdict.Judgement {

	var mine [][]string
	for _, r := range rows {
		if c := cells(r, 5); strings.EqualFold(c[1], machine) {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.no_channels"))
	}
	if network == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("mpcom1.no_inventory"))
	}
	var down []string
	for _, c := range mine {
		up := slices.ContainsFunc(network.Interfaces, func(i source.Interface) bool { return i.Name == c[2] && i.State == "up" }) ||
			slices.Contains(network.Tunnels, c[2])
		if !up {
			down = append(down, c[0]+" ("+c[2]+")")
		}
	}
	if len(down) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.tunnels_down", "list", down))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.tunnels_up", "count", len(mine)))
}

// JudgeEV11 needs every product of P-07 (`producto | certificacion | referencia | vigencia`) certified in
// force.
func JudgeEV11(rows []string, now time.Time) verdict.Judgement {
	var expired []string
	for _, r := range rows {
		c := cells(r, 4)
		until, ok := opcont2.Date(c[3])
		if c[2] == "" || !ok || until.Before(now) {
			expired = append(expired, c[0])
		}
	}
	if len(expired) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.products_uncertified", "list", expired))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.products_certified", "count", len(rows)))
}

// JudgeEV10 needs every change FIM saw under the channel configurations of P-06 covered by a request of
// op.exp.5.
func JudgeEV10(fim []source.FIMChange, paths []string, requests []opexp5.Request, machine string, since time.Time) verdict.Judgement {

	var mine []source.FIMChange
	for _, f := range fim {
		if slices.ContainsFunc(paths, func(p string) bool { return f.Path == p || strings.HasPrefix(f.Path, strings.TrimSuffix(p, "/")+"/") }) {
			mine = append(mine, f)
		}
	}
	changes := opexp5.Changes(mine, nil, since)
	if bare := opexp5.Uncovered(changes, requests, machine); len(bare) > 0 {
		list := make([]string, len(bare))
		for i, c := range bare {
			list[i] = c.String()
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom3.changes_unrequested", "list", list))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom3.changes_requested", "count", len(changes)))
}

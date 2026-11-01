// Package mpcom4 judges mp.com.4, segregation of networks: every machine in a declared segment, flows between
// segments authorised, no machine bridging segments, wireless kept apart, the chosen way of segmenting in
// place and incidents contained in their segment.
package mpcom4

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

// Purposes of a segment in P-01.
const (
	Users    = "usuarios"
	Services = "servicios"
	Admin    = "administracion"
	Wireless = "inalambrico"
)

// Segment is a row of P-01 (`segmento | proposito | rango | vlan`).
type Segment struct {
	Name, Purpose, VLAN string
	Range               netip.Prefix
}

func ParseSegments(rows []string) []Segment {
	var out []Segment
	for _, r := range rows {
		c := cells(r, 4)
		p, err := netip.ParsePrefix(c[2])
		if c[0] == "" || err != nil {
			continue
		}
		out = append(out, Segment{Name: c[0], Purpose: strings.ReplaceAll(opcont2.Person(c[1]), " ", "_"), Range: p.Masked(), VLAN: c[3]})
	}
	return out
}

// Of is the segment of an address: the narrowest range holding it.
func Of(segments []Segment, address string) (Segment, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return Segment{}, false
	}
	best, found := Segment{}, false
	for _, s := range segments {
		if s.Range.Contains(ip.Unmap()) && (!found || s.Range.Bits() > best.Range.Bits()) {
			best, found = s, true
		}
	}
	return best, found
}

// routable leaves out loopback and link-local addresses, which are in no segment.
func routable(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

// SegmentsOf are the segments a machine has addresses in, and its addresses in none.
func SegmentsOf(segments []Segment, network *source.Network) (in []string, outside []string) {
	if network == nil {
		return nil, nil
	}
	for _, a := range network.Addresses {
		if !routable(a) {
			continue
		}
		if s, ok := Of(segments, a); ok {
			if !slices.Contains(in, s.Name) {
				in = append(in, s.Name)
			}
		} else {
			outside = append(outside, a)
		}
	}
	return in, outside
}

// JudgeEV01 needs every address of the machine in a segment of P-01.
func JudgeEV01(segments []Segment, network *source.Network) verdict.Judgement {
	if network == nil {
		return verdictGap("mpcom1.no_inventory")
	}
	in, outside := SegmentsOf(segments, network)
	if len(outside) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.addresses_outside", "list", outside))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.in_segments", "list", in))
}

// Allowed tells whether a flow between two segments is in P-02 (`origen | destino | protocolo | puerto`):
// segments by name or `*`.
func Allowed(from, to Segment, f source.Flow, matrix []string) bool {
	if from.Name == to.Name {
		return true
	}
	return slices.ContainsFunc(matrix, func(r string) bool {
		c := cells(r, 4)
		segment := func(name string, s Segment) bool { return name == "*" || strings.EqualFold(name, s.Name) }
		protocol := strings.ToLower(c[2])
		return segment(c[0], from) && segment(c[1], to) &&
			(protocol == "" || protocol == "*" || strings.EqualFold(protocol, f.Protocol)) && mpcom1.MatchPort(c[3], f.Port)
	})
}

// JudgeEV02 needs every flow the interconnection points let through between two segments allowed by P-02.
func JudgeEV02(flows []source.Flow, segments []Segment, matrix []string) verdict.Judgement {
	var leaks []string
	between := 0
	for _, f := range flows {
		from, okFrom := Of(segments, f.Source)
		to, okTo := Of(segments, f.Destination)
		if !okFrom || !okTo || from.Name == to.Name {
			continue
		}
		between += f.Count
		if !Allowed(from, to, f, matrix) {
			leaks = append(leaks, from.Name+" → "+to.Name+" "+f.Protocol+"/"+f.Port+" ("+f.Source+" → "+f.Destination+")")
		}
	}
	if len(leaks) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.leaks", "list", leaks))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.flows_allowed", "count", between))
}

// JudgeEV03 needs the machine in one segment, unless P-05 names it as an interconnection point.
func JudgeEV03(segments []Segment, network *source.Network, machine string, points []string) verdict.Judgement {
	if network == nil {
		return verdictGap("mpcom1.no_inventory")
	}
	in, _ := SegmentsOf(segments, network)
	if len(in) <= 1 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.one_segment"))
	}
	if slices.ContainsFunc(points, func(r string) bool { return strings.EqualFold(cells(r, 3)[2], machine) }) {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.declared_point", "list", in))
	}
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.bridge", "list", in))
}

// JudgeEV04 needs every wireless interface of the machine up with its addresses in a wireless segment.
func JudgeEV04(segments []Segment, network *source.Network) verdict.Judgement {
	if network == nil {
		return verdictGap("mpcom1.no_inventory")
	}
	var mixed []string
	wireless := 0
	for _, i := range network.Interfaces {
		if i.State != "up" || !(strings.EqualFold(i.Type, "wireless") || strings.HasPrefix(i.Name, "wl")) {
			continue
		}
		wireless++
		for _, a := range network.ByInterface[i.Name] {
			if s, ok := Of(segments, a); !ok || s.Purpose != Wireless {
				mixed = append(mixed, i.Name+" "+a)
			}
		}
	}
	if len(mixed) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.wireless_mixed", "list", mixed))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.wireless_apart", "count", wireless))
}

// Modalities of P-03.
const (
	VLAN     = "vlan"
	VPN      = "vpn"
	Physical = "fisica"
)

// JudgeEV07 needs the way of segmenting of P-03 in place: every segment with its VLAN, or the machine
// reaching its segment through a tunnel.
func JudgeEV07(modality string, segments []Segment, network *source.Network) verdict.Judgement {
	switch modality {
	case VLAN:
		var untagged []string
		for _, s := range segments {
			if s.VLAN == "" {
				untagged = append(untagged, s.Name)
			}
		}
		if len(untagged) > 0 {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.segments_untagged", "list", untagged))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.segments_tagged", "count", len(segments)))
	case VPN:
		if network == nil {
			return verdictGap("mpcom1.no_inventory")
		}
		if slices.ContainsFunc(network.Interfaces, func(i source.Interface) bool { return i.State == "up" && mpcom1.Tunnel(i.Type, i.Name) }) {
			return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.tunnel_up"))
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.no_tunnel"))
	}
	return verdict.Explain(verdict.NotApplicable, "", catalog.Says("mpcom4.modality", "modality", modality))
}

// JudgeEV08 needs segments for users, services and administration in P-01.
func JudgeEV08(segments []Segment) verdict.Judgement {
	var missing []string
	for _, p := range []string{Users, Services, Admin} {
		if !slices.ContainsFunc(segments, func(s Segment) bool { return s.Purpose == p }) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.purposes_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.purposes"))
}

// JudgeEV09 needs every incident of op.exp.7 kept in one segment: the machines it involves in the same one.
func JudgeEV09(incidents []opexp7.Incident, segmentOf func(machine string) []string) verdict.Judgement {
	var spread []catalog.Message
	for _, in := range incidents {
		var seen []string
		for _, m := range in.Systems() {
			for _, s := range segmentOf(m) {
				if !slices.Contains(seen, s) {
					seen = append(seen, s)
				}
			}
		}
		if len(seen) > 1 {
			slices.Sort(seen)
			spread = append(spread, catalog.Says("item.name_list", "name", in.ID, "list", seen))
		}
	}
	if len(spread) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpcom4.incidents_spread", "list", spread))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpcom4.incidents_contained", "count", len(incidents)))
}

func verdictGap(code string) verdict.Judgement {
	return passes.Gap(verdict.CauseCollection, catalog.Says(code))
}

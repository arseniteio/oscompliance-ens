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

const (
	Users    = "usuarios"
	Services = "servicios"
	Admin    = "administracion"
	Wireless = "inalambrico"
)

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

func routable(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
}

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

const (
	VLAN     = "vlan"
	VPN      = "vpn"
	Physical = "fisica"
)

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

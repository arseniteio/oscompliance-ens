// Package mpeq4 judges mp.eq.4, other devices on the network: the devices each machine sees next to it
// inventoried, their flows within what their type may do, their own logs reaching Wazuh, and a way to wipe
// the storage of those that keep information.
package mpeq4

import (
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

// Device is a row of P-01 (`dispositivo | tipo | direccion | mac | responsable | almacenamiento`).
type Device struct {
	Name, Type, Address, MAC string
	Storage                  bool
}

func ParseDevices(rows []string) []Device {
	var out []Device
	for _, r := range rows {
		c := cells(r, 6)
		if c[0] == "" {
			continue
		}
		out = append(out, Device{Name: c[0], Type: c[1], Address: c[2], MAC: strings.ToLower(c[3]), Storage: opcont2.Person(c[5]) == "si"})
	}
	return out
}

// Known tells whether a neighbour is an inventoried device or a machine of the fleet.
func Known(n fact.Neighbour, devices []Device, fleet map[string]bool) bool {
	return fleet[n.IP] || slices.ContainsFunc(devices, func(d Device) bool {
		return (d.MAC != "" && d.MAC == strings.ToLower(n.MAC)) || (d.Address != "" && d.Address == n.IP)
	})
}

// JudgeEV01 needs the machine to see its network: a neighbour table read.
func JudgeEV01(s *fact.NeighbourSnapshot) verdict.Judgement {
	switch {
	case s == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.NeighbourSnapshotFact))
	case s.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("neighbours", s.Status, s.Error))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq4.seen", "count", len(s.Neighbours)))
}

// JudgeEV02 needs every device the machine sees next to it in P-01 or among the machines of the fleet.
func JudgeEV02(s *fact.NeighbourSnapshot, devices []Device, fleet map[string]bool) verdict.Judgement {
	if j := JudgeEV01(s); j.Status != verdict.Compliant {
		return j
	}
	var unknown []string
	for _, n := range s.Neighbours {
		if !Known(n, devices, fleet) {
			unknown = append(unknown, n.IP+" "+n.MAC)
		}
	}
	if len(unknown) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq4.uninventoried", "list", unknown))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq4.all_known", "count", len(s.Neighbours)))
}

// JudgeEV03 needs every flow of an inventoried device allowed for its type by P-02 (`tipo | destino |
// protocolo | puerto`), whichever end the device is.
func JudgeEV03(flows []source.Flow, devices []Device, rules []string) verdict.Judgement {

	byAddress := map[string]Device{}
	for _, d := range devices {
		if d.Address != "" {
			byAddress[d.Address] = d
		}
	}
	allowed := func(d Device, peer string, f source.Flow) bool {
		return slices.ContainsFunc(rules, func(r string) bool {
			c := cells(r, 4)
			protocol := strings.ToLower(c[2])
			return strings.EqualFold(c[0], d.Type) && mpcom1.Match(c[1], peer) &&
				(protocol == "" || protocol == "*" || strings.EqualFold(protocol, f.Protocol)) && mpcom1.MatchPort(c[3], f.Port)
		})
	}

	var outside []string
	checked := 0
	for _, f := range flows {
		for _, end := range []struct{ device, peer string }{{f.Source, f.Destination}, {f.Destination, f.Source}} {
			d, ok := byAddress[end.device]
			if !ok {
				continue
			}
			checked += f.Count
			if !allowed(d, end.peer, f) {
				outside = append(outside, d.Name+": "+f.Source+" → "+f.Destination+" "+f.Protocol+"/"+f.Port)
			}
		}
	}
	if len(outside) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq4.flows_outside", "list", outside))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq4.flows_allowed", "count", checked))
}

// JudgeEV08 needs every device of P-01 with storage to have its wipe in P-05 (`dispositivo | almacenamiento
// | metodo | cuando`).
func JudgeEV08(devices []Device, wipes []string) verdict.Judgement {
	var missing []string
	with := 0
	for _, d := range devices {
		if !d.Storage {
			continue
		}
		with++
		if !slices.ContainsFunc(wipes, func(r string) bool { c := cells(r, 3); return strings.EqualFold(c[0], d.Name) && c[2] != "" }) {
			missing = append(missing, d.Name)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mpeq4.no_wipe", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mpeq4.wipes", "count", with))
}

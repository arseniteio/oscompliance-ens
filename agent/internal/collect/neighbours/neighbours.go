package neighbours

import (
	"bufio"
	"sort"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	ARP string
}

var Default = Config{ARP: "/proc/net/arp"}

const unresolved = "00:00:00:00:00:00"

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.NeighbourSnapshot{Envelope: e.Envelope(fact.NeighbourSnapshotFact), Status: fact.SourceRead, Neighbours: []fact.Neighbour{}}

	data, err := fsread.ReadFile(cfg.ARP)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	s.Neighbours = parse(string(data))
	return e.Emit(s)
}

func parse(table string) []fact.Neighbour {

	seen := map[string]bool{}
	out := []fact.Neighbour{}

	lines := bufio.NewScanner(strings.NewReader(table))
	for header := true; lines.Scan(); header = false {
		f := strings.Fields(lines.Text())
		if header || len(f) < 6 {
			continue
		}
		ip, mac, device := f[0], strings.ToLower(f[3]), f[5]
		if mac == unresolved || seen[ip+device] {
			continue
		}
		seen[ip+device] = true
		out = append(out, fact.Neighbour{IP: ip, MAC: mac, Interface: device})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].IP != out[j].IP {
			return out[i].IP < out[j].IP
		}
		return out[i].Interface < out[j].Interface
	})
	return out
}

package opacc6

import (
	"net/netip"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
)

type Zones struct {
	prefixes []netip.Prefix
	local    bool
}

func ParseZones(lines []string) (Zones, catalog.Message) {

	var z Zones

	for _, line := range lines {

		value, _, _ := strings.Cut(strings.TrimSpace(line), " ")
		value = strings.TrimSpace(value)

		switch {
		case value == "":
			continue
		case strings.EqualFold(value, "local"):
			z.local = true
			continue
		}

		if p, err := netip.ParsePrefix(value); err == nil {
			z.prefixes = append(z.prefixes, p.Masked())
			continue
		}

		if a, err := netip.ParseAddr(value); err == nil {
			z.prefixes = append(z.prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}

		return Zones{}, catalog.Says("opacc6.not_zone", "value", value)
	}

	return z, catalog.Message{}
}

func (z Zones) Controlled(origin string) (controlled, known bool) {

	if origin == "local" {
		return z.local, true
	}

	a, err := netip.ParseAddr(strings.TrimSpace(origin))
	if err != nil {
		return false, false
	}
	a = a.Unmap()

	for _, p := range z.prefixes {
		if p.Contains(a) {
			return true, true
		}
	}

	return false, true
}

package opacc6

import (
	"fmt"
	"net/netip"
	"strings"
)

// Zones is P-02: the controlled zones, as networks, single addresses and
// "local" (the physical console).
type Zones struct {
	prefixes []netip.Prefix
	local    bool
}

// ParseZones reads P-02, one zone per line; text after the first blank is a
// comment. A line that is none of the three makes the whole list unusable:
// a mistyped range would turn a controlled zone into an uncontrolled one.
func ParseZones(lines []string) (Zones, string) {

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

		return Zones{}, fmt.Sprintf("%q is not a network, an address or local", value)
	}

	return z, ""
}

// Controlled says whether an origin is in a controlled zone; known is false
// when the origin is not an address ("" for an sshd login Wazuh could not
// decode).
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

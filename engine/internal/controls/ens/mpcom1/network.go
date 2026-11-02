package mpcom1

import (
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

func Match(network, address string) bool {
	if Anywhere(network) {
		return true
	}
	network = strings.TrimSpace(network)
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	if p, err := netip.ParsePrefix(network); err == nil {
		return p.Contains(ip)
	}
	a, err := netip.ParseAddr(network)
	return err == nil && a == ip
}

func Anywhere(network string) bool {
	switch strings.TrimSpace(strings.ToLower(network)) {
	case "", "*", "any", "0.0.0.0/0", "::/0":
		return true
	}
	return false
}

func MatchPort(spec, port string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "*" || spec == "" || strings.EqualFold(spec, "any") {
		return true
	}
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return false
	}
	from, to, isRange := strings.Cut(spec, "-")
	a, errA := strconv.Atoi(strings.TrimSpace(from))
	b := a
	if isRange {
		var errB error
		b, errB = strconv.Atoi(strings.TrimSpace(to))
		if errB != nil {
			return false
		}
	}
	return errA == nil && p >= a && p <= b
}

func Public(address string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	shared := netip.MustParsePrefix("100.64.0.0/10")
	return !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || shared.Contains(ip))
}

func Expected(name string, patterns []string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool {
		ok, err := path.Match(strings.TrimSpace(p), name)
		return err == nil && ok
	})
}

var AdminPorts = []int{22, 23, 139, 161, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017}

var TunnelTools = []string{"openvpn", "openconnect", "vpnc", "charon", "tailscaled", "zerotier-one", "ngrok", "cloudflared",
	"frpc", "chisel", "autossh", "sshuttle", "stunnel", "stunnel4", "iodine", "ptunnel", "dns2tcp", "gost", "tmate",
	"teamviewerd", "anydesk", "rustdesk"}

var tunnelTypes = []string{"tunnel", "ppp", "tun", "tap", "wireguard"}

var tunnelPrefixes = []string{"tun", "tap", "wg", "ppp", "ipsec", "vti", "gre", "tailscale", "zt"}

func Tunnel(typ, name string) bool {
	return slices.Contains(tunnelTypes, strings.ToLower(typ)) || slices.ContainsFunc(tunnelPrefixes, func(p string) bool { return strings.HasPrefix(name, p) })
}

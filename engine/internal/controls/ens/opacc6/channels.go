package opacc6

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type Listening struct {
	Snapshot *fact.ListeningSnapshot
	Sockets  []fact.ListeningSocket
}

func (l Listening) Gap() (verdict.Judgement, bool) {

	switch {
	case l.Snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.no_listening_snapshot_in_the_window")), true
	case l.Snapshot.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.listening_sockets_unreadable_a", "a", l.Snapshot.Error)), true
	case len(l.Sockets) < l.Snapshot.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.listening_read_a_incomplete_b_of_c_liste", "a", l.Snapshot.RunID, "b", len(l.Sockets), "c", l.Snapshot.RecordsEmitted)), true
	case len(l.Sockets) > 0 && !l.Snapshot.ProcessesMatched:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.listening_sockets_not_matched_to_process")), true
	}

	return verdict.Judgement{}, false
}

const (
	KindAuthentication = "autenticacion"
	KindTransport      = "transporte"
)

type Channel struct {
	Name      string
	Kind      string
	Encrypted bool
	Ports     []int
	Addresses []string
	Processes []string

	Units   []string
	Enabled []string
}

func channelOf(s fact.ListeningSocket) (name, kind string, encrypted, known bool) {

	process := strings.ToLower(s.Process)
	unit := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(s.Unit), ".service"), ".socket")

	switch {
	case process == "sshd" || process == "sshd-session" || unit == "ssh" || unit == "sshd":
		return "ssh", KindAuthentication, true, true
	case process == "slapd" && s.Port == 636:
		return "ldaps", KindAuthentication, true, true
	case process == "slapd":
		return "ldap", KindAuthentication, false, true
	case process == "xrdp" || unit == "xrdp":
		return "rdp", KindAuthentication, true, true
	case strings.Contains(process, "vnc"):
		return "vnc", KindAuthentication, false, true
	case process == "telnetd" || process == "in.telnetd":
		return "telnet", KindAuthentication, false, true
	case process == "vsftpd" || process == "proftpd" || process == "pure-ftpd":
		return "ftp", KindAuthentication, false, true
	case process == "cockpit-ws" || unit == "cockpit":
		return "cockpit", KindAuthentication, true, true
	case process == "miniserv.pl" || unit == "webmin":
		return "webmin", KindAuthentication, true, true
	case process == "openvpn":
		return "openvpn", KindTransport, true, true
	case process == "tailscaled":
		return "tailscale", KindTransport, true, true
	}

	return "", "", false, false
}

func (l Listening) Channels() (channels []Channel, other []string) {

	byName := map[string]*Channel{}

	for _, s := range l.Sockets {

		name, kind, encrypted, known := channelOf(s)

		if !known {
			other = append(other, fmt.Sprintf("%s/%d %s", s.Protocol, s.Port, s.Process))
			continue
		}

		c, ok := byName[name]
		if !ok {
			c = &Channel{Name: name, Kind: kind, Encrypted: encrypted}
			byName[name] = c
		}

		c.Ports = appendNew(c.Ports, s.Port)
		c.Addresses = appendNew(c.Addresses, s.Address)
		if s.Process != "" {
			c.Processes = appendNew(c.Processes, s.Process)
		}
		for _, u := range [][2]string{{s.Unit, s.UnitEnabled}, {s.SocketUnit, s.SocketEnabled}} {
			if u[0] != "" && !slices.Contains(c.Units, u[0]) {
				c.Units = append(c.Units, u[0])
				c.Enabled = append(c.Enabled, u[1])
			}
		}
	}

	for _, c := range byName {
		channels = append(channels, *c)
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].Name < channels[j].Name })
	sort.Strings(other)

	return channels, other
}

func (l Listening) Exposed(c Channel) []string {

	var out []string

	for _, a := range c.Addresses {

		if a != "0.0.0.0" && a != "::" {
			out = appendNew(out, a)
			continue
		}

		for _, m := range l.Snapshot.Addresses {
			if (a == "0.0.0.0") == !strings.Contains(m, ":") {
				out = appendNew(out, m)
			}
		}
	}

	return out
}

func appendNew[T comparable](list []T, v T) []T {
	if slices.Contains(list, v) {
		return list
	}
	return append(list, v)
}

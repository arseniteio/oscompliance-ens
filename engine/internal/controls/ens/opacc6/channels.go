package opacc6

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// Listening is one read of the listening sockets of an agent.
type Listening struct {
	Snapshot *fact.ListeningSnapshot
	Sockets  []fact.ListeningSocket
}

// Gap says why the read cannot be used.
func (l Listening) Gap() (verdict.Judgement, bool) {

	switch {
	case l.Snapshot == nil:
		return notEvaluable(verdict.CauseCollection, "no listening_snapshot in the window"), true
	case l.Snapshot.Status != fact.SourceRead:
		return notEvaluable(verdict.CauseCollection, "listening sockets unreadable: "+l.Snapshot.Error), true
	case len(l.Sockets) < l.Snapshot.RecordsEmitted:
		return notEvaluable(verdict.CauseCollection, fmt.Sprintf("listening read %s incomplete: %d of %d listening_socket received", l.Snapshot.RunID, len(l.Sockets), l.Snapshot.RecordsEmitted)), true
	case len(l.Sockets) > 0 && !l.Snapshot.ProcessesMatched:
		return notEvaluable(verdict.CauseCollection, "listening sockets not matched to processes: the agent does not run as root"), true
	}

	return verdict.Judgement{}, false
}

// Kinds of channel, as v1: an authentication channel lets a person log in,
// a transport channel carries other channels (a VPN).
const (
	KindAuthentication = "autenticacion"
	KindTransport      = "transporte"
)

// Channel is a remote access channel the machine offers.
type Channel struct {
	Name      string // as P-07 names it: ssh, rdp, vnc...
	Kind      string
	Encrypted bool
	Ports     []int
	Addresses []string // as bound; 0.0.0.0 and :: are every address
	Processes []string
	// Units and their is-enabled states, service and socket alike.
	Units   []string
	Enabled []string
}

// channelOf names the channel of a process or unit, and whether it
// encrypts. ldap on 389 is counted as not encrypted: StartTLS cannot be
// seen from the configuration of every directory.
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

// Channels groups the listening sockets by channel; other lists the
// listeners that are not remote access channels (web servers, databases).
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

// Exposed lists the concrete addresses a channel answers on: a wildcard
// is every address of the machine.
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

func notEvaluable(cause verdict.Cause, reason string) verdict.Judgement {
	return verdict.Judgement{Status: verdict.NotEvaluable, Cause: cause, Reason: reason}
}

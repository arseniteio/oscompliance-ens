package listening

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/host"

	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	Proc string

	Systemctl string

	Addresses func() ([]net.Addr, error)
}

const (
	tcpListen = "0A"
	udpBound  = "07"
)

type socketLine struct {
	protocol string
	address  string
	port     int
	inode    string
}

func Collect(e *emit.Emitter, cfg Config) error {

	snapshot := fact.ListeningSnapshot{Envelope: e.Envelope(fact.ListeningSnapshotFact), Status: fact.SourceRead, Addresses: []string{}}

	var sockets []socketLine

	for _, table := range []struct{ file, protocol, state string }{
		{"net/tcp", "tcp", tcpListen}, {"net/tcp6", "tcp", tcpListen},
		{"net/udp", "udp", udpBound}, {"net/udp6", "udp", udpBound},
	} {
		lines, err := readSocketTable(filepath.Join(cfg.Proc, table.file), table.protocol, table.state)

		if errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(table.file, "6") {
			continue
		}

		if err != nil {
			snapshot.Status, snapshot.Error = fact.SourceUnreadable, err.Error()
			return e.Emit(snapshot)
		}

		sockets = append(sockets, lines...)
	}

	snapshot.Addresses = interfaceAddresses(cfg.Addresses)

	owners, matched := socketOwners(cfg.Proc)
	snapshot.ProcessesMatched = matched

	units := newUnits(cfg.Systemctl)
	snapshot.Systemd = units.status

	seen := map[string]bool{}

	for _, s := range sockets {

		key := fmt.Sprintf("%s %s %d", s.protocol, s.address, s.port)
		if seen[key] {
			continue
		}
		seen[key] = true

		record := fact.ListeningSocket{Envelope: e.Envelope(fact.ListeningSocketFact), Protocol: s.protocol, Address: s.address, Port: s.port}

		if pid, ok := owners[s.inode]; ok {
			record.PID = pid
			record.Process = readTrimmed(filepath.Join(cfg.Proc, strconv.Itoa(pid), "comm"))
			record.Exe, _ = os.Readlink(filepath.Join(cfg.Proc, strconv.Itoa(pid), "exe"))
			record.Unit = unitOf(filepath.Join(cfg.Proc, strconv.Itoa(pid), "cgroup"))
		}

		if socketUnit, service, ok := units.socketFor(s.address, s.port); ok {
			record.SocketUnit, record.SocketEnabled = socketUnit, units.enabled(socketUnit)
			if record.Unit == "" || record.Unit == "init.scope" {
				record.Unit = service
			}
		}

		if record.Unit == "init.scope" {
			record.Unit = ""
		}
		if record.Unit != "" {
			record.UnitEnabled = units.enabled(record.Unit)
		}

		if err := e.Emit(record); err != nil {
			return err
		}
		snapshot.RecordsEmitted++
	}

	return e.Emit(snapshot)
}

func readSocketTable(path, protocol, state string) ([]socketLine, error) {

	file, err := fsread.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var out []socketLine
	scanner := bufio.NewScanner(file)
	scanner.Scan()

	for scanner.Scan() {

		f := strings.Fields(scanner.Text())
		if len(f) < 10 || f[3] != state {
			continue
		}

		if protocol == "udp" && !strings.HasSuffix(f[2], ":0000") {
			continue
		}

		ip, port, err := parseHexAddress(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		if ip.IsLoopback() {
			continue
		}

		out = append(out, socketLine{protocol: protocol, address: ip.String(), port: port, inode: f[9]})
	}

	return out, scanner.Err()
}

func parseHexAddress(s string) (net.IP, int, error) {

	addr, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("address %q", s)
	}

	raw, err := hex.DecodeString(addr)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("address %q", s)
	}

	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		binary.BigEndian.PutUint32(ip[i:], binary.LittleEndian.Uint32(raw[i:]))
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("port %q", s)
	}

	return ip, int(port), nil
}

func socketOwners(proc string) (map[string]int, bool) {

	owners := map[string]int{}
	matched := false

	dirs, _ := os.ReadDir(proc)

	for _, d := range dirs {

		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}

		fds, err := os.ReadDir(filepath.Join(proc, d.Name(), "fd"))
		if err != nil {
			continue
		}
		matched = true

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(proc, d.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, taken := owners[inode]; !taken {
				owners[inode] = pid
			}
		}
	}

	return owners, matched
}

func unitOf(cgroup string) string {

	data, err := fsread.ReadFile(cgroup)
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || (parts[1] != "" && parts[1] != "name=systemd") {
			continue
		}

		segments := strings.Split(parts[2], "/")
		for i := len(segments) - 1; i >= 0; i-- {
			s := segments[i]
			if strings.HasSuffix(s, ".service") || strings.HasSuffix(s, ".scope") || strings.HasSuffix(s, ".socket") {
				return s
			}
		}
	}

	return ""
}

func interfaceAddresses(list func() ([]net.Addr, error)) []string {

	if list == nil {
		list = net.InterfaceAddrs
	}

	addrs, err := list()
	if err != nil {
		return []string{}
	}

	out := []string{}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}

	sort.Strings(out)
	return out
}

type units struct {
	systemctl string
	status    string
	sockets   []socketUnit
	states    map[string]string
}

type socketUnit struct {
	listen, unit, activates string
}

func newUnits(systemctl string) *units {

	u := &units{systemctl: systemctl, status: fact.SourceAbsent, states: map[string]string{}}

	if systemctl == "" {
		return u
	}
	if _, err := os.Stat(systemctl); err != nil {
		return u
	}

	out, err := host.Run(systemctl, "list-sockets", "--all", "--no-legend", "--no-pager", "--full")
	if err != nil {
		u.status = fact.SourceError
		return u
	}
	u.status = fact.SourceRead

	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 {
			u.sockets = append(u.sockets, socketUnit{listen: f[0], unit: f[1], activates: f[2]})
		}
	}

	return u
}

func (u *units) socketFor(address string, port int) (unit, activates string, ok bool) {

	p := strconv.Itoa(port)

	for _, s := range u.sockets {

		host, sport, err := net.SplitHostPort(s.listen)
		if err != nil {
			host, sport = "", s.listen
		}

		if sport != p {
			continue
		}

		if host == "" || host == "::" || host == "0.0.0.0" || host == "*" || host == address {
			return s.unit, s.activates, true
		}
	}

	return "", "", false
}

func (u *units) enabled(unit string) string {

	if u.status != fact.SourceRead {
		return ""
	}

	if state, ok := u.states[unit]; ok {
		return state
	}

	ctx, cancel := context.WithTimeout(context.Background(), host.CommandTimeout)
	defer cancel()

	out, _ := exec.CommandContext(ctx, u.systemctl, "is-enabled", unit).Output()
	state := strings.TrimSpace(string(out))
	u.states[unit] = state

	return state
}

func readTrimmed(path string) string {
	data, _ := fsread.ReadFile(path)
	return strings.TrimSpace(string(data))
}

package listening

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func TestParseHexAddress(t *testing.T) {

	for in, want := range map[string]string{
		"0100007F:0016":                         "127.0.0.1:22",
		"00000000:0016":                         "0.0.0.0:22",
		"050AA8C0:01BB":                         "192.168.10.5:443",
		"00000000000000000000000000000000:0016": ":::22",
		"000080FE000000000000000001000000:0035": "fe80::1:53",
	} {
		ip, port, err := parseHexAddress(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := ip.String() + ":" + strconv.Itoa(port); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestCollectListening(t *testing.T) {

	proc := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	collecttest.Write(t, filepath.Join(proc, "net/tcp"), header+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0\n"+
		"   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0\n"+
		"   2: 050AA8C0:0016 0B0AA8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0\n")
	collecttest.Write(t, filepath.Join(proc, "net/udp"), header+
		"   0: 00000000:04AA 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2001 2 0\n"+
		"   1: 050AA8C0:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 2002 2 0\n")

	collecttest.Write(t, filepath.Join(proc, "812/comm"), "sshd\n")
	collecttest.Write(t, filepath.Join(proc, "812/cgroup"), "0::/system.slice/ssh.service\n")
	if err := os.MkdirAll(filepath.Join(proc, "812/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1001]", filepath.Join(proc, "812/fd/3")); err != nil {
		t.Fatal(err)
	}

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Proc: proc, Addresses: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}, &net.IPNet{IP: net.ParseIP("192.168.10.5"), Mask: net.CIDRMask(24, 32)}}, nil
		}})
	})

	if len(facts) != 3 {
		t.Fatalf("want 2 sockets and the snapshot, got %v", facts)
	}

	ssh, vpn, snapshot := facts[0], facts[1], facts[2]

	if ssh["local_address"] != "0.0.0.0" || ssh["local_port"] != 22.0 || ssh["process_name"] != "sshd" || ssh["unit"] != "ssh.service" || ssh["process_id"] != 812.0 {
		t.Errorf("ssh: %v", ssh)
	}
	if vpn["protocol"] != "udp" || vpn["local_port"] != 1194.0 || vpn["process_id"] != nil {
		t.Errorf("udp: %v", vpn)
	}
	if snapshot["records_emitted"] != 2.0 || snapshot["systemd"] != "absent" || snapshot["processes_matched"] != true {
		t.Errorf("snapshot: %v", snapshot)
	}
	if addrs := snapshot["addresses"].([]any); len(addrs) != 1 || addrs[0] != "192.168.10.5" {
		t.Errorf("addresses: %v", addrs)
	}
}

package neighbours

import (
	"path/filepath"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

const table = `IP address       HW type     Flags       HW address            Mask     Device
192.168.167.1    0x1         0x2         D6:F1:41:94:0C:01     *        eth0
192.168.167.9    0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.5         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
`

func TestCollect(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "arp"), table)

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, Config{ARP: filepath.Join(dir, "arp")}) })

	got := facts[0]["neighbours"].([]any)
	if facts[0]["status"] != "read" || len(got) != 2 {
		t.Fatalf("snapshot: %v", facts[0])
	}
	if first := got[0].(map[string]any); first["ip"] != "10.0.0.5" || first["interface"] != "eth1" {
		t.Errorf("order: %v", got)
	}
	if second := got[1].(map[string]any); second["mac"] != "d6:f1:41:94:0c:01" {
		t.Errorf("mac: %v", second)
	}

	facts = collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, Config{ARP: filepath.Join(dir, "none")}) })
	if facts[0]["status"] != "unreadable" {
		t.Errorf("no table: %v", facts[0])
	}
}

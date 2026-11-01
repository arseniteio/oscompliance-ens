package timesync

import (
	"path/filepath"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
)

func TestParsers(t *testing.T) {

	sync, offset := parseTracking("Reference ID    : C0A80101 (192.168.1.1)\nSystem time     : 0.000250000 seconds slow of NTP time\nLeap status     : Normal\n")
	if !sync || offset != -0.00025 {
		t.Errorf("tracking: %v %v", sync, offset)
	}
	if s, _ := parseTracking("Leap status     : Not synchronised\n"); s {
		t.Error("not synchronised")
	}
	got := parseSources("MS Name/IP address         Stratum Poll Reach LastRx Last sample\n===\n^* 192.168.1.1  2   6   377    12   +12us[  +15us] +/-  20ms\n^- 10.0.0.9  3   6   377    12   +1ms[  +1ms] +/-  20ms\n")
	if len(got) != 1 || got[0] != "192.168.1.1" {
		t.Errorf("sources: %v", got)
	}

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "chrony.conf"), "pool ntp.ubuntu.com iburst\nserver time.cloudflare.com iburst nts\n")
	if !authenticated([]string{filepath.Join(dir, "*.conf")}) {
		t.Error("nts source")
	}
}

package windevice

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func device(t *testing.T, out string) map[string]any {
	t.Helper()
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out)) })
	if len(facts) != 1 {
		t.Fatalf("%d facts", len(facts))
	}
	return facts[0]
}

func TestEncryptedLaptopWithScreenLock(t *testing.T) {
	d := device(t, `{"chassis":10,"graphical":true,"inactivity_timeout":600,"system_drive":"C:","bitlocker":"read","volumes":[{"drive":"C:","protection":1,"method":7},{"drive":"D:","protection":0,"method":0}],"resolvers":["10.0.0.2"],"cpus":8,"load":12,"memory":40}`)
	for k, want := range map[string]any{"portable": true, "root_encrypted": true, "lock_enabled": true, "lock_idle_delay_seconds": 600.0, "root_device": "C:", "cpu_count": 8.0, "status": "read"} {
		if d[k] != want {
			t.Errorf("%s = %v, want %v", k, d[k], want)
		}
	}
}

func TestServerWithoutBitLocker(t *testing.T) {
	d := device(t, `{"chassis":17,"graphical":false,"inactivity_timeout":null,"system_drive":"C:","bitlocker":"absent","volumes":[],"resolvers":null,"cpus":2,"load":0,"memory":71}`)
	if d["portable"] != false || d["root_encrypted"] != false || d["status"] != "read" {
		t.Errorf("got %v", d)
	}
	if _, ok := d["lock_enabled"]; ok {
		t.Error("lock reported without the policy value")
	}
}

func TestSuspendedProtectionIsNotEncryption(t *testing.T) {
	d := device(t, `{"chassis":9,"system_drive":"C:","bitlocker":"read","volumes":[{"drive":"C:","protection":0,"method":7}]}`)
	if d["root_encrypted"] != false {
		t.Errorf("got %v", d)
	}
}

func TestBitLockerQueryError(t *testing.T) {
	d := device(t, `{"bitlocker":"error","bitlocker_error":"Access denied"}`)
	if d["status"] != "error" || d["error"] != "BitLocker: Access denied" {
		t.Errorf("got %v", d)
	}
}

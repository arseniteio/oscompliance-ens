package winservices

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

const sample = `{"services":[
{"name":"TermService","state":"Running","start":"Manual","exit":0,"pid":1200},
{"name":"UmRdpService","state":"Running","start":"Manual","exit":0,"pid":1200},
{"name":"gupdate","state":"Stopped","start":"Auto","exit":0,"pid":0},
{"name":"WazuhSvc","state":"Stopped","start":"Auto","exit":1067,"pid":0}],
"processes":{"1200":{"name":"svchost","path":"C:\\Windows\\System32\\svchost.exe"},"4":{"name":"System","path":""}},
"sockets":[{"protocol":"tcp","address":"0.0.0.0","port":3389,"pid":1200},{"protocol":"tcp","address":"0.0.0.0","port":3389,"pid":1200},{"protocol":"tcp","address":"::","port":445,"pid":4}],
"addresses":["10.0.0.5","::1"]}`

func TestUnits(t *testing.T) {
	m := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectUnits(e, winps.Static(sample)) })[0]
	units, failed := m["units"].([]any), m["failed"].([]any)
	if len(units) != 2 || len(failed) != 1 || failed[0] != "WazuhSvc" {
		t.Errorf("got %v", m)
	}
}

func TestListening(t *testing.T) {
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectListening(e, winps.Static(sample)) })
	if len(facts) != 3 {
		t.Fatalf("got %v", facts)
	}
	rdp := facts[0]
	if rdp["local_port"] != 3389.0 || rdp["unit"] != "TermService" || rdp["unit_enabled"] != "manual" || rdp["process_name"] != "svchost" {
		t.Errorf("rdp %v", rdp)
	}
	if _, ok := facts[1]["unit"]; ok || facts[1]["process_name"] != "System" {
		t.Errorf("smb %v", facts[1])
	}
	if facts[2]["records_emitted"] != 2.0 {
		t.Errorf("snapshot %v", facts[2])
	}
}

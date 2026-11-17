package wintime

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func collect(t *testing.T, out string) map[string]any {
	t.Helper()
	return collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out)) })[0]
}

func TestSpanishDomainMember(t *testing.T) {
	m := collect(t, `{"running":true,"type":"NT5DS","ntp_server":"","status":["Indicador de salto: 0(sin advertencia)","Capa: 3 (referencia secundaria - sincronizada mediante (S)NTP)","Precisión: -23 (119.209ns por tic)","Retraso de raíz: 0.0312500s","Dispersión de raíz: 7.7756000s","Id. de referencia: 0x0A000002 (IP de origen:  10.0.0.2)","Última sincronización correcta: 17/11/2026 12:00:00","Origen: DC01.corp.local","Intervalo de sondeo: 10 (1024s)"]}`)
	if m["tool"] != Tool || m["synchronised"] != true || m["authenticated"] != true || m["sources"].([]any)[0] != "DC01.corp.local" {
		t.Errorf("got %v", m)
	}
}

func TestUnsynchronisedNTP(t *testing.T) {
	m := collect(t, `{"running":true,"type":"NTP","ntp_server":"time.windows.com,0x9 pool.ntp.org","status":["Leap Indicator: 3(not synchronized)","Stratum: 0 (unspecified)","Precision: -23","Root Delay: 0s","Root Dispersion: 0s","ReferenceId: 0x00000000","Last Successful Sync Time: unspecified","Source: Local CMOS Clock","Poll Interval: 10 (1024s)"]}`)
	sources := m["sources"].([]any)
	if m["synchronised"] != false || m["authenticated"] != false || len(sources) != 3 || sources[1] != "time.windows.com" {
		t.Errorf("got %v", m)
	}
}

func TestStoppedService(t *testing.T) {
	if m := collect(t, `{"running":false,"type":"NTP","status":[]}`); m["tool"] != "none" {
		t.Errorf("got %v", m)
	}
}

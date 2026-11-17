package windefender

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func collect(t *testing.T, out string, cfg Config) map[string]any {
	t.Helper()
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out), cfg) })
	return facts[0]
}

func TestDefenderRunning(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "netsh.exe"), "")

	m := collect(t, `{"installed":true,"running":true,"version":"4.18.24090.11","realtime":true,"signatures":"2026-11-17T06:00:00.0000000Z","signature_schedule_day":0,"signature_interval":0,"archive_scanning":true,"last_scan":"2026-11-16T03:00:00.0000000Z","applocker":"absent"}`, Config{Responses: dir})

	products := m["products"].([]any)
	if len(products) != 1 || products[0].(map[string]any)["product"] != Product || products[0].(map[string]any)["running"] != true {
		t.Errorf("products %v", products)
	}
	var got []string
	for _, s := range m["enabled_settings"].([]any) {
		got = append(got, s.(string))
	}
	if !slices.Equal(got, []string{"proteccion_tiempo_real", "actualizacion_automatica_firmas", "analisis_comprimidos", "registro_syslog"}) {
		t.Errorf("settings %v", got)
	}
	if m["signatures"] != "2026-11-17T06:00:00.0000000Z" || m["allowlist"] != "absent" || len(m["responses"].([]any)) != 1 {
		t.Errorf("got %v", m)
	}
}

func TestNoDefender(t *testing.T) {
	m := collect(t, `{"installed":false,"running":false,"applocker":"enforcing"}`, Config{Responses: t.TempDir()})
	if len(m["products"].([]any)) != 0 || m["allowlist"] != "enforcing" || len(m["enabled_settings"].([]any)) != 0 {
		t.Errorf("got %v", m)
	}
}

package winfirewall

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func TestProfilesBecomeChains(t *testing.T) {

	out := `{"running":true,"profiles":[{"name":"Domain","enabled":"True","inbound":"NotConfigured","outbound":"NotConfigured"},{"name":"Public","enabled":"False","inbound":"Block","outbound":"Block"}]}`
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out)) })

	chains := facts[0]["chains"].([]any)
	want := []struct{ table, hook, policy string }{{"domain", "input", "drop"}, {"domain", "output", "accept"}, {"public", "input", "accept"}, {"public", "output", "accept"}}
	if len(chains) != len(want) {
		t.Fatalf("chains %v", chains)
	}
	for i, w := range want {
		c := chains[i].(map[string]any)
		if c["table"] != w.table || c["hook"] != w.hook || c["policy"] != w.policy {
			t.Errorf("chain %d = %v, want %+v", i, c, w)
		}
	}
}

func TestStoppedFirewall(t *testing.T) {
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(`{"running":false,"profiles":[]}`)) })
	if facts[0]["tool"] != "none" || facts[0]["status"] != "read" {
		t.Errorf("got %v", facts[0])
	}
}

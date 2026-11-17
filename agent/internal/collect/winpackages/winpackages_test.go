package winpackages

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func TestPackagesAndFeatures(t *testing.T) {
	out := `{"packages":["Wazuh Agent","7-Zip 23.01","Wazuh Agent"],"features":["feature:AD-Domain-Services"]}`
	m := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out)) })[0]
	got := m["packages"].([]any)
	if len(got) != 3 || got[0] != "7-Zip 23.01" || got[2] != "feature:AD-Domain-Services" || m["manager"] != Manager {
		t.Errorf("got %v", m)
	}
}

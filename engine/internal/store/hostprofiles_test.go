package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/hostprofile"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestHostProfileMappingCoversEveryField(t *testing.T) {

	inv := &source.HostInventory{OS: "Ubuntu", Version: "24.04", Platform: "ubuntu", Hostname: "web-01", Architecture: "x86_64", Packages: []string{"nginx", "gdm3"}}
	p := hostprofile.Build(verdict.Agent{ID: "001", Name: "web-01"}, []string{"ens"}, inv, catalog.Signals(), time.Now(), "test")

	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	properties := hostProfileMapping["mappings"].(map[string]any)["properties"].(map[string]any)
	checkMapped(t, "", doc, properties)
}

func checkMapped(t *testing.T, prefix string, doc map[string]any, properties map[string]any) {
	for field, value := range doc {
		m, ok := properties[field].(map[string]any)
		if !ok {
			t.Errorf("%s%s is not in the strict mapping", prefix, field)
			continue
		}
		switch v := value.(type) {
		case map[string]any:
			checkMapped(t, prefix+field+".", v, m["properties"].(map[string]any))
		case []any:
			for _, item := range v {
				if obj, ok := item.(map[string]any); ok {
					checkMapped(t, prefix+field+".", obj, m["properties"].(map[string]any))
				}
			}
		}
	}
}

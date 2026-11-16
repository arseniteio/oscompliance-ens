package scope

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
)

func TestFleet(t *testing.T) {
	f := FleetOf(map[string]source.Reporting{"001": {Name: "Web01"}, "002": {Name: "db01"}})
	if !f.Has("web01") || f.Has("mail01") {
		t.Error("has")
	}
	if id, ok := f.ID("DB01"); !ok || id != "002" {
		t.Errorf("id %s", id)
	}
	if len(f.IDs()) != 3 || !f.Any(func(id string) bool { return id == source.ManagerID }) {
		t.Errorf("ids %v", f.IDs())
	}
	if !Carrier("000") || Carrier("001") {
		t.Error("carrier")
	}
}

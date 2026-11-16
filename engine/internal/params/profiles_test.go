package params

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
)

func profiled(t *testing.T) *Config {
	t.Helper()
	c := load(t)
	c.UseProfiles([]catalog.Profile{
		{ID: "zimbra", Name: "Zimbra", Layer: catalog.LayerService, Match: []catalog.Condition{{Field: "service", Op: "has", Value: "zimbra"}},
			Values: map[string]map[string]any{"op.acc.1": {"P-03": []any{"zimbra", "postfix", "_apt"}}}},
		{ID: "madrid", Name: "Madrid", Layer: catalog.LayerSite, Match: []catalog.Condition{{Field: "group", Op: "has", Value: "ens-madrid"}},
			Values:  map[string]map[string]any{"op.acc.1": {"P-10": 1500.0, "P-11": []any{"admins-mad"}}},
			Replace: map[string][]string{"op.acc.1": {"P-11"}}},
	})
	c.UseHostFacts(map[string]catalog.HostFacts{
		"010": {Distro: "ubuntu-24.04", Role: "server", Services: []string{"zimbra"}},
		"011": {Distro: "ubuntu-22.04", Role: "server", Groups: []string{"ens-madrid"}},
		"012": {Distro: "rocky-9", Role: "server", Services: []string{"zimbra"}},
		"001": {Distro: "ubuntu-24.04", Services: []string{"zimbra"}},
		"004": {Distro: "ubuntu-24.04", Services: []string{"zimbra"}},
		"000": {Distro: "rhel-9", Role: "manager"},
	})
	return c
}

func TestProfilesUnionListsAcrossLayers(t *testing.T) {
	c := profiled(t)

	got, err := c.List("010", "op.acc.1", "P-03")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"zimbra", "postfix", "_apt", "sshd", "root"} {
		if !slices.Contains(got, want) {
			t.Errorf("P-03 misses %s: %v", want, got)
		}
	}
	if n := len(got); n != len(slices.Compact(slices.Sorted(slices.Values(got)))) {
		t.Errorf("P-03 has duplicates: %v", got)
	}

	r, _ := c.Explain("010", "op.acc.1", "P-03")
	if want := []Source{{"profile", "zimbra"}, {"profile", "ubuntu"}}; !slices.Equal(r.Sources, want) {
		t.Errorf("sources %v, want %v", r.Sources, want)
	}
}

func TestProfilesMostSpecificScalarWins(t *testing.T) {
	c := profiled(t)

	if n, err := c.Number("011", "op.acc.1", "P-10"); err != nil || n != 1500 {
		t.Errorf("P-10 = %v, %v; want 1500 from the site profile", n, err)
	}
	if got, _ := c.List("011", "op.acc.1", "P-11"); !slices.Equal(got, []string{"admins-mad"}) {
		t.Errorf("replace did not cut the distro list: %v", got)
	}
}

func TestProfilesOnlyMatchingDistro(t *testing.T) {
	c := profiled(t)

	got, err := c.List("012", "op.acc.1", "P-03")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"zimbra", "postfix", "_apt"}) {
		t.Errorf("rocky got Ubuntu values: %v", got)
	}
}

func TestExplicitValuesBeatProfiles(t *testing.T) {
	c := profiled(t)

	if got, _ := c.List("001", "op.acc.1", "P-07"); !slices.Contains(got, "ana") {
		t.Errorf("agent value lost: %v", got)
	}
	r, _ := c.Explain("001", "op.acc.1", "P-03")
	if !slices.Equal(r.Sources, []Source{{"template", "linux-ubuntu"}}) {
		t.Errorf("assigned template should win over profiles, got %v", r.Sources)
	}
	if _, err := c.List("004", "op.acc.1", "P-03"); err != nil {
		t.Fatal(err)
	}
	r, _ = c.Explain("004", "op.acc.1", "P-03")
	if !slices.Equal(r.Sources, []Source{{"organisation", ""}}) {
		t.Errorf("template none must skip profiles too, got %v", r.Sources)
	}
}

func TestManagerGetsItsBuiltinProfile(t *testing.T) {
	c := profiled(t)
	r, ok := c.Explain("000", "op.acc.1", "P-10")
	if !ok || !slices.Equal(r.Sources, []Source{{"profile", "manager-wazuh"}}) {
		t.Errorf("manager P-10 from %v", r.Sources)
	}
}

func TestWithoutHostFactsNothingChanges(t *testing.T) {
	before, after := load(t), load(t)
	after.UseProfiles(nil)
	for _, agent := range []string{"001", "002", "003", "004", "005", "006", "007", "999"} {
		for _, param := range []string{"P-03", "P-07", "P-10", "P-11"} {
			a, errA := before.List(agent, "op.acc.1", param)
			b, errB := after.List(agent, "op.acc.1", param)
			if !slices.Equal(a, b) || (errA == nil) != (errB == nil) {
				t.Errorf("%s %s changed: %v %v -> %v %v", agent, param, a, errA, b, errB)
			}
		}
	}
}

func TestLoadProfiles(t *testing.T) {

	client := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": [{"_source": {"documentType": "PROFILE", "configuration":
		{"id": "zimbra", "name": "Zimbra", "layer": "service", "match": [{"field": "service", "op": "has", "value": "zimbra"}],
		 "values": {"op.acc.1": {"P-03": ["zimbra"]}}}}}]}}`)

	got, err := LoadProfiles(context.Background(), client, "wazuh-ens-configuration")
	if err != nil || len(got) != 1 || got[0].ID != "zimbra" {
		t.Fatalf("LoadProfiles = %v, %v", got, err)
	}

	bad := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": [{"_source": {"configuration": {"id": "x", "name": "X", "layer": "nowhere", "match": []}}}]}}`)
	if _, err := LoadProfiles(context.Background(), bad, "wazuh-ens-configuration"); err == nil {
		t.Error("an invalid stored profile must be reported")
	}

	missing := indexerAnswering(t, http.StatusNotFound, `{}`)
	if got, err := LoadProfiles(context.Background(), missing, "wazuh-ens-configuration"); err != nil || got != nil {
		t.Errorf("missing index: %v, %v", got, err)
	}
}

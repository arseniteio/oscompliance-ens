package catalog

import "testing"

func TestDefaultConfigurationScopesTheEnsGroupAtMediumLevel(t *testing.T) {

	d := Default()

	if d.EnsLevel != "MEDIO" {
		t.Errorf("ensLevel = %q, want MEDIO", d.EnsLevel)
	}
	if d.Scope.Mode != "group" || len(d.Scope.GroupIDs) != 1 || d.Scope.GroupIDs[0] != "ens" {
		t.Errorf("scope = %+v, want group ens", d.Scope)
	}
}

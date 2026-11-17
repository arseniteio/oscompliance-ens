package catalog

import (
	"slices"
	"testing"
)

func TestHostSignals(t *testing.T) {

	s := Signals()
	families := []string{"debian", "rhel", "suse", "windows"}
	roles := []string{"", "workstation"}
	seen := map[string]bool{}

	for _, d := range s.Distros {
		if seen[d.ID] {
			t.Errorf("distro %s listed twice", d.ID)
		}
		seen[d.ID] = true
		if !slices.Contains(families, d.Family) {
			t.Errorf("distro %s: unknown family %q", d.ID, d.Family)
		}
		if !slices.Contains([]string{"major", "major.minor", "none"}, d.Version) {
			t.Errorf("distro %s: version must be major, major.minor or none, got %q", d.ID, d.Version)
		}
		if !slices.Contains(roles, d.Role) {
			t.Errorf("distro %s: unknown role %q", d.ID, d.Role)
		}
		if len(d.Platforms) == 0 && len(d.Names) == 0 {
			t.Errorf("distro %s matches nothing", d.ID)
		}
	}

	services := map[string]bool{}
	for _, sig := range s.Services {
		services[sig.ID] = true
	}
	for _, sig := range slices.Concat(s.Roles, s.Services) {
		if len(sig.Packages) == 0 {
			t.Errorf("%s matches no package", sig.ID)
		}
		for _, u := range sig.Unless {
			if !services[u] {
				t.Errorf("%s: unless names unknown service %q", sig.ID, u)
			}
		}
	}
}

func TestPackageSignalMatch(t *testing.T) {

	db := PackageSignal{ID: "database", Packages: []string{"mariadb-server", "postgresql-1*"}}

	for name, want := range map[string]bool{
		"mariadb-server":    true,
		"postgresql-16":     true,
		"postgresql-common": false,
		"mariadb-client":    false,
	} {
		if got := db.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}

	exact, prefixes := HostSignals{Services: []PackageSignal{db, {ID: "web", Packages: []string{"nginx", "mariadb-server"}}}}.PackageNames()
	if !slices.Equal(exact, []string{"mariadb-server", "nginx"}) || !slices.Equal(prefixes, []string{"postgresql-1"}) {
		t.Errorf("PackageNames() = %v, %v", exact, prefixes)
	}
}

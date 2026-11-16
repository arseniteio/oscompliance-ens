package hostprofile

import (
	"slices"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestBuild(t *testing.T) {

	now := time.Date(2026, 11, 16, 18, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		agent    string
		inv      *source.HostInventory
		distro   string
		family   string
		role     string
		services []string
	}{
		{
			name:   "ubuntu workstation",
			agent:  "001",
			inv:    &source.HostInventory{OS: "Ubuntu", Version: "24.04.1 LTS (Noble Numbat)", Platform: "ubuntu", Packages: []string{"gdm3", "openssh-server"}},
			distro: "ubuntu-24.04", family: "debian", role: RoleWorkstation, services: []string{},
		},
		{
			name:   "rocky zimbra hides its bundled ldap",
			agent:  "002",
			inv:    &source.HostInventory{OS: "Rocky Linux", Version: "9.4 (Blue Onyx)", Platform: "rocky", Packages: []string{"zimbra-core", "openldap-servers", "httpd"}},
			distro: "rocky-9", family: "rhel", role: RoleServer, services: []string{"zimbra", "web"},
		},
		{
			name:   "debian openldap",
			agent:  "003",
			inv:    &source.HostInventory{OS: "Debian GNU/Linux", Version: "12 (bookworm)", Platform: "debian", Packages: []string{"slapd", "postgresql-16"}},
			distro: "debian-12", family: "debian", role: RoleServer, services: []string{"openldap", "database"},
		},
		{
			name:   "manager by id, distro by name",
			agent:  "000",
			inv:    &source.HostInventory{OS: "Red Hat Enterprise Linux", Version: "9.5"},
			distro: "rhel-9", family: "rhel", role: RoleManager, services: []string{},
		},
		{
			name:  "agent without inventory",
			agent: "004",
			role:  RoleServer, services: []string{},
		},
		{
			name:  "unknown platform keeps no distro",
			agent: "005",
			inv:   &source.HostInventory{OS: "Gentoo", Version: "2.15", Platform: "gentoo"},
			role:  RoleServer, services: []string{},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Build(verdict.Agent{ID: c.agent, Name: "host-" + c.agent}, []string{"ens"}, c.inv, catalog.Signals(), now, "test")
			if p.Distro != c.distro || p.Family != c.family || p.Role != c.role || !slices.Equal(p.Services, c.services) {
				t.Errorf("got distro %q family %q role %q services %v; want %q %q %q %v", p.Distro, p.Family, p.Role, p.Services, c.distro, c.family, c.role, c.services)
			}
			if p.Timestamp != "2026-11-16T18:00:00Z" || p.Agent.ID != c.agent || !slices.Equal(p.Groups, []string{"ens"}) {
				t.Errorf("envelope: %+v", p)
			}
		})
	}
}

func TestBuildExplainsEverySignal(t *testing.T) {

	inv := &source.HostInventory{OS: "Ubuntu", Version: "22.04", Platform: "ubuntu", Packages: []string{"nginx", "lightdm"}}
	p := Build(verdict.Agent{ID: "010"}, nil, inv, catalog.Signals(), time.Now(), "test")

	want := []Signal{
		{Field: "distro", Value: "ubuntu-22.04", From: "os.platform:ubuntu"},
		{Field: "role", Value: RoleWorkstation, From: "package:lightdm"},
		{Field: "service", Value: "web", From: "package:nginx"},
	}
	if !slices.Equal(p.Signals, want) {
		t.Errorf("signals %+v, want %+v", p.Signals, want)
	}
}

func TestVersion(t *testing.T) {
	for _, c := range []struct{ full, precision, want string }{
		{"24.04.1 LTS (Noble Numbat)", "major.minor", "24.04"},
		{"9.4 (Blue Onyx)", "major", "9"},
		{"12 (bookworm)", "major.minor", "12"},
		{"2023", "major", "2023"},
		{"rolling", "major", ""},
		{"", "major", ""},
	} {
		if got := version(c.full, c.precision); got != c.want {
			t.Errorf("version(%q, %q) = %q, want %q", c.full, c.precision, got, c.want)
		}
	}
}

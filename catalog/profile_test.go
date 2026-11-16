package catalog

import (
	"slices"
	"strings"
	"testing"
)

func TestBuiltinProfilesAreValid(t *testing.T) {
	profiles := BuiltinProfiles()
	if len(profiles) == 0 {
		t.Fatal("no built-in profiles")
	}
	for _, p := range profiles {
		if errs := p.Validate(); len(errs) > 0 {
			t.Errorf("%s: %v", p.ID, errs)
		}
	}
}

func TestBuiltinProfilesMatchTheirTemplates(t *testing.T) {
	for id, template := range map[string]string{"ubuntu": "linux-ubuntu", "manager-wazuh": "manager-wazuh"} {
		i := slices.IndexFunc(BuiltinProfiles(), func(p Profile) bool { return p.ID == id })
		if i < 0 {
			t.Fatalf("no built-in profile %s", id)
		}
		p := BuiltinProfiles()[i]
		for controlID, values := range p.Values {
			tpl, ok := BuiltinTemplate(template, controlID)
			if !ok || len(tpl.Values[controlID]) != len(values) {
				t.Errorf("%s %s differs from template %s", id, controlID, template)
			}
		}
	}
}

func TestProfileMatches(t *testing.T) {

	host := HostFacts{Distro: "rocky-9", Family: "rhel", Role: "server", Hostname: "mail-mad-01", Services: []string{"zimbra", "web"}, Groups: []string{"ens", "ens-madrid"}}

	cases := []struct {
		match []Condition
		want  bool
	}{
		{[]Condition{{"service", "has", "zimbra"}}, true},
		{[]Condition{{"service", "has", "Zimbra "}}, true},
		{[]Condition{{"service", "has_not", "openldap"}}, true},
		{[]Condition{{"service", "has", "openldap"}}, false},
		{[]Condition{{"distro", "matches", "rocky-*"}, {"role", "is", "server"}}, true},
		{[]Condition{{"distro", "matches", "ubuntu-*"}}, false},
		{[]Condition{{"family", "is_not", "debian"}}, true},
		{[]Condition{{"group", "has", "ens-madrid"}, {"hostname", "matches", "mail-*"}}, true},
		{[]Condition{{"role", "is", "workstation"}}, false},
		{nil, false},
	}

	for _, c := range cases {
		if got := (Profile{Match: c.match}).Matches(host); got != c.want {
			t.Errorf("%v: got %v, want %v", c.match, got, c.want)
		}
	}
}

func TestProfileValidate(t *testing.T) {

	p := Profile{
		ID: "Zimbra Mail", Layer: "servicios",
		Match: []Condition{{"service", "is", "zimbra"}, {"colour", "is", "red"}, {"distro", "matches", ""}},
		Values: map[string]map[string]any{
			"op.acc.1": {"P-03": 3.0, "P-99": []any{"x"}, "P-04": []any{"guest"}, "P-10": "mil"},
			"op.zz.9":  {"P-01": 1.0},
		},
		Replace: map[string][]string{"op.acc.1": {"P-11"}},
	}

	want := []string{
		`id "Zimbra Mail"`,
		"name is empty",
		`layer "servicios"`,
		"match 1: service takes has, has_not",
		`match 2: unknown field "colour"`,
		"match 3: value is empty",
		"op.acc.1 P-03: must be a list",
		"op.acc.1 P-04 is set once for the organisation",
		"op.acc.1 P-10: must be a number",
		"P-99 does not exist in op.acc.1",
		"control op.zz.9 does not exist",
		"replace op.acc.1 P-11 has no value",
	}

	errs := strings.Join(p.Validate(), "\n")
	for _, w := range want {
		if !strings.Contains(errs, w) {
			t.Errorf("missing %q in:\n%s", w, errs)
		}
	}
}

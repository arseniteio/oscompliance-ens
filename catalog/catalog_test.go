package catalog

import "testing"

func TestOpAcc1(t *testing.T) {
	c, ok := LookupControl("op.acc.1")
	if !ok || len(c.Evidences) != 8 {
		t.Fatalf("op.acc.1: %v %+v", ok, c)
	}

	if c.Status != "ACTIVE" || len(c.Requirements) != 8 {
		t.Fatalf("requirements: %s %d", c.Status, len(c.Requirements))
	}

	ev07, _ := c.Evidence("EV-07")
	if ev07.AppliesAt("BAJO") || !ev07.AppliesAt("MEDIO") || !ev07.AppliesAt("ALTO") {
		t.Errorf("EV-07 levels: %v", ev07.Levels)
	}

	for param, want := range map[string]string{"P-03": ClassPlatform, "P-04": ClassOrganisation, "P-07": ClassSystem, "P-99": ""} {
		if got := ParameterClass("op.acc.1", param); got != want {
			t.Errorf("%s: class %q, want %q", param, got, want)
		}
	}
}

func TestTemplates(t *testing.T) {
	linux, ok := TypeDefaultTemplate("op.acc.1", "linux")
	if !ok || linux.ID != "linux-ubuntu" || linux.Values["op.acc.1"]["P-10"] != float64(1000) {
		t.Errorf("linux default: %v %+v", ok, linux)
	}

	if w, ok := TypeDefaultTemplate("op.acc.1", "windows"); !ok || w.Values["op.acc.1"]["P-03"] != nil {
		t.Errorf("windows: %v %+v", ok, w)
	}

	if _, ok := TypeDefaultTemplate("op.acc.1", "manager"); ok {
		t.Error("manager has no op.acc.1 template")
	}

	if _, ok := BuiltinTemplate("zimbra-ldap", "op.acc.1"); !ok {
		t.Error("zimbra-ldap by id")
	}
}

func TestCatalogConsistency(t *testing.T) {
	levels := map[string]bool{"BAJO": true, "MEDIO": true, "ALTO": true}
	classes := map[string]bool{ClassOrganisation: true, ClassSystem: true, ClassPlatform: true}

	all := Controls()
	if len(all) < 6 {
		t.Fatalf("want at least op.acc.1 to op.acc.6, got %d controls", len(all))
	}

	for _, c := range all {
		if c.Title == "" || c.Status == "" || len(c.Requirements) == 0 {
			t.Errorf("%s: title %q, status %q, %d requirements", c.Control, c.Title, c.Status, len(c.Requirements))
		}

		used := map[string]bool{}
		for _, r := range c.Requirements {
			for _, l := range r.Levels {
				if !levels[l] {
					t.Errorf("%s %s: level %q", c.Control, r.ID, l)
				}
			}
			for _, id := range r.EvidenceIDs {
				if _, ok := c.Evidence(id); !ok {
					t.Errorf("%s %s names unknown evidence %s", c.Control, r.ID, id)
				}
				used[id] = true
			}
		}

		for _, e := range c.Evidences {
			if !used[e.ID] {
				t.Errorf("%s %s accredits no requirement", c.Control, e.ID)
			}
		}

		for id, p := range c.Parameters {
			if !classes[p.Class] {
				t.Errorf("%s %s: class %q", c.Control, id, p.Class)
			}
		}
	}
}

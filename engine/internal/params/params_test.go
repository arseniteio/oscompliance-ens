package params

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

const active = `{
  "global": {"ensLevel": "MEDIO"},
  "controls": [
    {"controlId": "op.acc.1", "enabled": true, "parameters": [
      {"id": "P-03", "value": ["common-svc"]},
      {"id": "P-04", "value": ["admin", " guest ", ""]},
      {"id": "P-05", "value": 30},
      {"id": "P-06", "value": "^adm.*$", "matchMode": "regex"},
      {"id": "P-07", "value": []},
      {"id": "P-08", "value": "many"},
      {"id": "P-09", "value": ""},
      {"id": "P-10", "value": " 1000 "},
      {"id": "P-12", "value": "root\n\nadmin\n"},
      {"id": "P-15", "value": true},
      {"id": "P-16", "value": "Sí"},
      {"id": "P-17", "value": "no"},
      {"id": "P-18", "value": "quizá"}
    ]},
    {"controlId": "op.acc.2", "enabled": false, "parameters": []}
  ],
  "templates": [
    {"id": "custom-svc", "controlId": "op.acc.1", "name": "Custom", "values": {"P-03": "(svc|app)-[a-z]+"}, "matchModes": {"P-03": "regex"}}
  ],
  "agents": {
    "001": {"detectedType": "linux", "controls": {"op.acc.1": {"templateId": "linux-ubuntu",
            "parameters": {"P-04": ["ignored"], "P-07": ["jgomez | srv01 | ops", "ana", " | srv02 | x", "pepe |"]}}}},
    "002": {"detectedType": "linux", "controls": {"op.acc.1": {"parameters": {"P-11": ["wheel"]}}}},
    "003": {"detectedType": "windows"},
    "004": {"detectedType": "linux", "controls": {"op.acc.1": {"templateId": "none"}}},
    "005": {"detectedType": "linux", "controls": {"op.acc.1": {"templateId": "custom-svc"}}},
    "006": {"typeOverride": "zimbra-ldap", "detectedType": "linux"},
    "007": {"detectedType": "router"}
  }
}`

func load(t *testing.T) *Config {
	t.Helper()
	var c Config
	if err := json.Unmarshal([]byte(active), &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

func TestResolution(t *testing.T) {
	c := load(t)

	cases := []struct {
		agent, param string
		want         []string
		wantErr      error
	}{

		{"001", "P-04", []string{"admin", "guest"}, nil},

		{"001", "P-07", []string{"jgomez | srv01 | ops", "ana", "| srv02 | x", "pepe |"}, nil},

		{"002", "P-11", []string{"wheel"}, nil},

		{"001", "P-11", []string{"sudo", "wheel", "admin"}, nil},

		{"002", "P-01", []string{"Local"}, nil},

		{"003", "P-11", []string{"Administrators"}, nil},
		{"003", "P-03", []string{"common-svc"}, nil},

		{"004", "P-11", nil, ErrNotSet},
		{"004", "P-03", []string{"common-svc"}, nil},

		{"006", "P-01", []string{"LDAP"}, nil},

		{"007", "P-01", nil, ErrNotSet},

		{"999", "P-03", []string{"common-svc"}, nil},

		{"001", "P-12", []string{"root", "admin"}, nil},

		{"999", "P-09", nil, ErrNotSet},
		{"999", "P-99", nil, ErrNotSet},
	}

	for _, tc := range cases {
		got, err := c.List(tc.agent, "op.acc.1", tc.param)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s %s: want %v, got %v %v", tc.agent, tc.param, tc.wantErr, got, err)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %s: got %v %v, want %v", tc.agent, tc.param, got, err, tc.want)
		}
	}

	if _, err := c.List("999", "op.acc.1", "P-06"); err == nil || errors.Is(err, ErrNotSet) {
		t.Errorf("regex in List: want an error, got %v", err)
	}
}

func TestTemplateNumbersAndPatterns(t *testing.T) {
	c := load(t)

	for _, agent := range []string{"002", "999"} {
		if n, err := c.Number(agent, "op.acc.1", "P-10"); err != nil || n != 1000 {
			t.Errorf("%s P-10: %v %v", agent, n, err)
		}
	}

	m, err := c.Matcher("005", "op.acc.1", "P-03")
	if err != nil || !m.Match("svc-backup") || m.Match("common-svc") {
		t.Errorf("custom template pattern: %v %v", m, err)
	}

	m, err = c.Matcher("001", "op.acc.1", "P-03")
	if err != nil || !m.Match("www-data") || m.Match("common-svc") {
		t.Errorf("linux template list: %v %v", m, err)
	}
}

func TestLevelAndEnabled(t *testing.T) {
	c := load(t)

	if c.Level() != "MEDIO" || !c.ControlEnabled("op.acc.1") || c.ControlEnabled("op.acc.2") || !c.ControlEnabled("op.exp.1") {
		t.Errorf("level %q, op.acc.1 %v, op.acc.2 %v", c.Level(), c.ControlEnabled("op.acc.1"), c.ControlEnabled("op.acc.2"))
	}
}

func TestListColumn(t *testing.T) {
	c := load(t)

	got, err := c.ListColumn("001", "op.acc.1", "P-07", 0)
	if err != nil || !reflect.DeepEqual(got, []string{"jgomez", "ana", "pepe"}) {
		t.Errorf("usuario column: %v %v", got, err)
	}

	got, err = c.ListColumn("001", "op.acc.1", "P-07", 1)
	if err != nil || !reflect.DeepEqual(got, []string{"srv01", "srv02"}) {
		t.Errorf("sistema column: %v %v", got, err)
	}

	if _, err := c.ListColumn("002", "op.acc.1", "P-07", 0); !errors.Is(err, ErrNotSet) {
		t.Errorf("empty table: want ErrNotSet, got %v", err)
	}
}

func TestNumber(t *testing.T) {
	c := load(t)

	if n, err := c.Number("999", "op.acc.1", "P-05"); err != nil || n != 30 {
		t.Errorf("JSON number: %v %v", n, err)
	}
	if _, err := c.Number("999", "op.acc.1", "P-08"); err == nil || errors.Is(err, ErrNotSet) {
		t.Errorf("not a number: want a non-ErrNotSet error, got %v", err)
	}
	for _, id := range []string{"P-09", "P-99"} {
		if _, err := c.Number("999", "op.acc.1", id); !errors.Is(err, ErrNotSet) {
			t.Errorf("%s: want ErrNotSet, got %v", id, err)
		}
	}
}

func TestPatternMatcher(t *testing.T) {
	m, err := PatternMatcher("(adm|tmp)[0-9]*")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"adm": true, "tmp42": true, "admin": false, "xadm": false, "ADM": false} {
		if m.Match(name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
	for _, bad := range []string{"(a", " a ", string(make([]byte, MaxPatternLength+1))} {
		if _, err := PatternMatcher(bad); err == nil {
			t.Errorf("%q: want an error", bad[:min(len(bad), 10)])
		}
	}

	list := ListMatcher("admin", "guest")
	if !list.Match("ADMIN") || list.Match("guests") {
		t.Errorf("list matcher: %v", list)
	}
}

func TestBool(t *testing.T) {
	c := load(t)

	for id, want := range map[string]bool{"P-15": true, "P-16": true, "P-17": false} {
		if got, err := c.Bool("999", "op.acc.1", id); err != nil || got != want {
			t.Errorf("%s: %v %v", id, got, err)
		}
	}
	if _, err := c.Bool("999", "op.acc.1", "P-18"); err == nil || errors.Is(err, ErrNotSet) {
		t.Errorf("P-18: want a non-ErrNotSet error, got %v", err)
	}
	if _, err := c.Bool("999", "op.acc.1", "P-99"); !errors.Is(err, ErrNotSet) {
		t.Errorf("P-99: %v", err)
	}
}

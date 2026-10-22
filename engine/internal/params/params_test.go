package params

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// Shape copied from the lab's wazuh-ens-configuration, trimmed.
const active = `{
  "controls": [
    {"controlId": "op.acc.1", "parameters": [
      {"id": "P-03", "value": []},
      {"id": "P-04", "value": ["admin", " guest ", ""]},
      {"id": "P-05", "value": "root\n\nadmin\n"},
      {"id": "P-06", "value": "^adm.*$", "matchMode": "regex"},
      {"id": "P-08", "value": 30},
      {"id": "P-10", "value": " 1000 "},
      {"id": "P-13", "value": "many"},
      {"id": "P-14", "value": ""}
    ]}
  ],
  "agents": {
    "001": {"controls": {"op.acc.1": {"parameters": {"P-04": ["test"], "P-07": ["jgomez | srv01 | ops", "ana", " | srv02 | x", "pepe |"]}}}},
    "002": {"controls": {"op.acc.1": {"parameters": {"P-07": ["x"]}}}}
  }
}`

func TestList(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(active), &c); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		agent, param string
		want         []string
		wantErr      error // ErrNotSet, or nil; any other error is checked as non-nil
		anyErr       bool
	}{
		{"001", "P-04", []string{"test"}, nil, false},           // agent value wins
		{"002", "P-04", []string{"admin", "guest"}, nil, false}, // agent without P-04: control value, trimmed
		{"999", "P-04", []string{"admin", "guest"}, nil, false}, // unknown agent: control value
		{"001", "P-05", []string{"root", "admin"}, nil, false},  // one entry per line
		{"001", "P-03", nil, ErrNotSet, false},                  // empty list
		{"001", "P-99", nil, ErrNotSet, false},                  // missing
		{"001", "P-06", nil, nil, true},                         // regex: not supported
	}

	for _, tc := range cases {
		got, err := c.List(tc.agent, "op.acc.1", tc.param)

		switch {
		case tc.anyErr:
			if err == nil || errors.Is(err, ErrNotSet) {
				t.Errorf("%s %s: want a non-ErrNotSet error, got %v", tc.agent, tc.param, err)
			}
		case tc.wantErr != nil:
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s %s: want %v, got %v", tc.agent, tc.param, tc.wantErr, err)
			}
		default:
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s %s: got %v %v, want %v", tc.agent, tc.param, got, err, tc.want)
			}
		}
	}
}

func TestListColumn(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(active), &c); err != nil {
		t.Fatal(err)
	}

	got, err := c.ListColumn("001", "op.acc.1", "P-07", 0)
	if err != nil || !reflect.DeepEqual(got, []string{"jgomez", "ana", "pepe"}) {
		t.Errorf("usuario column: %v %v", got, err)
	}

	got, err = c.ListColumn("001", "op.acc.1", "P-07", 1)
	if err != nil || !reflect.DeepEqual(got, []string{"srv01", "srv02"}) {
		t.Errorf("sistema column: %v %v", got, err)
	}

	// Agent 002's P-07 is ["x"]: a one-column row has no rol column.
	if _, err := c.ListColumn("002", "op.acc.1", "P-07", 2); !errors.Is(err, ErrNotSet) {
		t.Errorf("column absent from every row: want ErrNotSet, got %v", err)
	}
}

func TestNumber(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(active), &c); err != nil {
		t.Fatal(err)
	}

	if n, err := c.Number("001", "op.acc.1", "P-08"); err != nil || n != 30 {
		t.Errorf("JSON number: %v %v", n, err)
	}
	if n, err := c.Number("001", "op.acc.1", "P-10"); err != nil || n != 1000 {
		t.Errorf("number as string: %v %v", n, err)
	}
	if _, err := c.Number("001", "op.acc.1", "P-13"); err == nil || errors.Is(err, ErrNotSet) {
		t.Errorf("not a number: want a non-ErrNotSet error, got %v", err)
	}
	for _, id := range []string{"P-14", "P-99"} {
		if _, err := c.Number("001", "op.acc.1", id); !errors.Is(err, ErrNotSet) {
			t.Errorf("%s: want ErrNotSet, got %v", id, err)
		}
	}
}

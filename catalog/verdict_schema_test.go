package catalog

import (
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestVerdictSchema(t *testing.T) {
	raw, err := os.Open("schemas/verdicts/verdict.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(raw)
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}

	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("verdict.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("verdict.json")
	if err != nil {
		t.Fatal(err)
	}

	const base = `"oscompliance_verdict":"1","@timestamp":"2026-10-22T12:00:00Z","control":"op.acc.1","evidence":"EV-07","agent":{"id":"001","name":"a"},"window_start":"2026-10-21T10:00:00Z","window_end":"2026-10-22T12:00:00Z","engine_version":"x"`

	cases := []struct {
		name  string
		extra string
		valid bool
	}{
		{"compliant", `"status":"COMPLIANT"`, true},
		{"compliant with reason", `"status":"COMPLIANT","reason":"2 accounts"`, true},
		{"non compliant", `"status":"NON_COMPLIANT","reason":"x"`, true},
		{"non compliant without reason", `"status":"NON_COMPLIANT"`, false},
		{"not evaluable", `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, true},
		{"not evaluable without cause", `"status":"NOT_EVALUABLE","reason":"x"`, false},
		{"not applicable", `"status":"NOT_APPLICABLE","reason":"EV-07 applies at MEDIO, ALTO; active ENS level BAJO"`, true},
		{"not applicable without reason", `"status":"NOT_APPLICABLE"`, false},
		{"not applicable with cause", `"status":"NOT_APPLICABLE","cause":"CONFIGURATION","reason":"x"`, false},
		{"unknown status", `"status":"CUMPLE"`, false},
	}

	for _, tc := range cases {
		v, err := jsonschema.UnmarshalJSON(strings.NewReader("{" + base + "," + tc.extra + "}"))
		if err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(v); (err == nil) != tc.valid {
			t.Errorf("%s: valid=%v, error %v", tc.name, tc.valid, err)
		}
	}
}

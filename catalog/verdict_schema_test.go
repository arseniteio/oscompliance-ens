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

	const base = `"oscompliance_verdict":"1","@timestamp":"2026-10-22T12:00:00Z","control":"op.acc.1","agent":{"id":"001","name":"a"},"window_start":"2026-10-21T10:00:00Z","window_end":"2026-10-22T12:00:00Z","engine_version":"x"`

	const ev = `"scope":"evidence","evidence":"EV-07",`
	const rq = `"scope":"requirement","requirement":"op.acc.1.4",`
	const ct = `"scope":"control",`

	cases := []struct {
		name  string
		extra string
		valid bool
	}{
		{"compliant", ev + `"status":"COMPLIANT"`, true},
		{"compliant with reason", ev + `"status":"COMPLIANT","reason":"2 accounts"`, true},
		{"non compliant", ev + `"status":"NON_COMPLIANT","reason":"x"`, true},
		{"non compliant without reason", ev + `"status":"NON_COMPLIANT"`, false},
		{"not evaluable", ev + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, true},
		{"not evaluable without cause", ev + `"status":"NOT_EVALUABLE","reason":"x"`, false},
		{"not applicable", ev + `"status":"NOT_APPLICABLE","reason":"EV-07 applies at MEDIO, ALTO; active ENS level BAJO"`, true},
		{"not applicable without reason", ev + `"status":"NOT_APPLICABLE"`, false},
		{"not applicable with cause", ev + `"status":"NOT_APPLICABLE","cause":"CONFIGURATION","reason":"x"`, false},
		{"unknown status", ev + `"status":"CUMPLE"`, false},
		{"no scope", `"evidence":"EV-07","status":"COMPLIANT"`, false},
		{"evidence scope without evidence", `"scope":"evidence","status":"COMPLIANT"`, false},
		{"requirement not evidenced", rq + `"status":"NON_COMPLIANT","reason":"not evidenced: EV-04 (CONFIGURATION)","evidenced":false`, true},
		{"requirement attested", rq + `"status":"COMPLIANT","evidenced":true,"attested":true,"reason":"attested by document: x"`, true},
		{"requirement never NOT_EVALUABLE", rq + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, false},
		{"requirement never PARTIAL", rq + `"status":"PARTIAL","reason":"x"`, false},
		{"requirement with evidence field", rq + `"evidence":"EV-01","status":"COMPLIANT"`, false},
		{"control partial", ct + `"status":"PARTIAL","reason":"6 of 8","score":75,"coverage":75,"applicable_requirements":8,"measured_requirements":6,"unmeasured_requirements":["op.acc.1.5","op.acc.1.r1.1"]`, true},
		{"control not applicable without score", ct + `"status":"NOT_APPLICABLE","reason":"no requirement applies"`, true},
		{"control score out of range", ct + `"status":"COMPLIANT","score":101`, false},
		{"control never NOT_EVALUABLE", ct + `"status":"NOT_EVALUABLE","cause":"COLLECTION","reason":"x"`, false},
		{"partial evidence", ev + `"status":"PARTIAL","reason":"x"`, false},
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

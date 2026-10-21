package fact

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const schemaDir = "../schemas/facts"

// compileSchemas loads every fact schema under its $id, so the relative $ref
// to the envelope resolves, and returns the payload schemas by fact name.
func compileSchemas(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()
	c.AssertFormat()

	files, err := filepath.Glob(filepath.Join(schemaDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no schemas in %s: %v", schemaDir, err)
	}

	ids := map[string]string{}

	for _, f := range files {
		raw, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(raw)
		raw.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}

		id, _ := doc.(map[string]any)["$id"].(string)
		if err := c.AddResource(id, doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		ids[strings.TrimSuffix(filepath.Base(f), ".v1.json")] = id
	}

	schemas := map[string]*jsonschema.Schema{}

	for name, id := range ids {
		s, err := c.Compile(id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name != "envelope" {
			schemas[name] = s
		}
	}

	return schemas
}

// validate checks one fact against the schema named by its "fact" field.
func validate(schemas map[string]*jsonschema.Schema, line []byte) error {

	v, err := jsonschema.UnmarshalJSON(strings.NewReader(string(line)))

	if err != nil {
		return err
	}

	name, _ := v.(map[string]any)["fact"].(string)

	s, ok := schemas[name]
	if !ok {
		return &unknownFact{name}
	}

	return s.Validate(v)
}

type unknownFact struct{ name string }

func (e *unknownFact) Error() string { return "no schema for fact " + e.name }

// examples returns every line of every file in examples/.
func examples(t *testing.T) [][]byte {
	t.Helper()

	files, _ := filepath.Glob(filepath.Join(schemaDir, "examples", "*.ndjson"))

	var lines [][]byte

	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, append([]byte(nil), scanner.Bytes()...))
		}
		file.Close()
	}

	if len(lines) == 0 {
		t.Fatal("no examples")
	}

	return lines
}

func TestExamplesAreValid(t *testing.T) {
	schemas := compileSchemas(t)

	for i, line := range examples(t) {
		if err := validate(schemas, line); err != nil {
			t.Errorf("example %d: %v\n%s", i, err, line)
		}
	}
}

// The Go types must write exactly what the schemas accept.
func TestGoTypesRoundTrip(t *testing.T) {
	schemas := compileSchemas(t)

	for i, line := range examples(t) {

		var probe Envelope
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatal(err)
		}

		var v any
		switch probe.Fact {
		case AccountRecordFact:
			v = &AccountRecord{}
		case AccountInventorySnapshotFact:
			v = &AccountInventorySnapshot{}
		case IdentityRecordFact:
			v = &IdentityRecord{}
		case IdentitySnapshotFact:
			v = &IdentitySnapshot{}
		default:
			t.Fatalf("example %d: no Go type for fact %q", i, probe.Fact)
		}

		if err := json.Unmarshal(line, v); err != nil {
			t.Fatal(err)
		}
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := validate(schemas, out); err != nil {
			t.Errorf("example %d after Go round trip: %v\n%s", i, err, out)
		}
	}
}

func TestSchemasRejectBadFacts(t *testing.T) {
	schemas := compileSchemas(t)

	const read = `{"oscompliance":"1","fact":"account_inventory_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","source":"passwd","source_path":"/etc/passwd","source_status":"read","uid_min":1000,"entries_total":3,"records_emitted":1,"duplicate_uids":[]}`
	const unread = `{"oscompliance":"1","fact":"account_inventory_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","source":"passwd","source_path":"/etc/passwd","source_status":"unreadable","source_error":"denied","uid_min":1000}`

	const identityRead = `{"oscompliance":"1","fact":"identity_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","passwd_path":"/etc/passwd","passwd_status":"read","shadow_path":"/etc/shadow","shadow_status":"read","records_emitted":2}`
	const shadowUnread = `{"oscompliance":"1","fact":"identity_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","passwd_path":"/etc/passwd","passwd_status":"read","shadow_path":"/etc/shadow","shadow_status":"unreadable","shadow_error":"denied"}`
	const identityRecord = `{"oscompliance":"1","fact":"identity_record","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","account_name":"a","uid":1000,"gid":1000,"shell":"/bin/bash","password_state":"set"}`

	cases := []struct {
		name string
		base string
		edit func(map[string]any)
	}{
		{"verdict field", read, func(m map[string]any) { m["estado"] = "CUMPLE" }},
		{"evidence id", read, func(m map[string]any) { m["evidence_id"] = "EV-01" }},
		{"error on a read snapshot", read, func(m map[string]any) { m["source_error"] = "x" }},
		{"read without duplicate_uids", read, func(m map[string]any) { delete(m, "duplicate_uids") }},
		{"ts not in UTC", read, func(m map[string]any) { m["ts"] = "2026-10-21T14:00:00+02:00" }},
		{"run_id not a UUID", read, func(m map[string]any) { m["run_id"] = "x" }},
		{"duplicate with one account", read, func(m map[string]any) {
			m["duplicate_uids"] = []any{map[string]any{"uid": 1, "account_names": []any{"a"}}}
		}},
		{"counters on an unread snapshot", unread, func(m map[string]any) { m["entries_total"] = 0 }},
		{"unread without source_error", unread, func(m map[string]any) { delete(m, "source_error") }},
		{"identity: records with shadow unread", shadowUnread, func(m map[string]any) { m["records_emitted"] = 0 }},
		{"identity: shadow unread without error", shadowUnread, func(m map[string]any) { delete(m, "shadow_error") }},
		{"identity: error on a read passwd", identityRead, func(m map[string]any) { m["passwd_error"] = "x" }},
		{"identity: both read without records_emitted", identityRead, func(m map[string]any) { delete(m, "records_emitted") }},
		{"identity: password hash", identityRecord, func(m map[string]any) { m["password_hash"] = "$6$abc" }},
		{"identity: unknown password_state", identityRecord, func(m map[string]any) { m["password_state"] = "expired" }},
		{"identity: expiry not a date", identityRecord, func(m map[string]any) { m["account_expires"] = "20612" }},
	}

	for _, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.base), &m); err != nil {
			t.Fatal(err)
		}
		c.edit(m)
		line, _ := json.Marshal(m)

		if validate(schemas, line) == nil {
			t.Errorf("%s: accepted %s", c.name, line)
		}
	}

	// The bases themselves are valid, so each rejection above is the edit's.
	for _, base := range []string{read, unread, identityRead, shadowUnread, identityRecord} {
		if err := validate(schemas, []byte(base)); err != nil {
			t.Errorf("base rejected: %v", err)
		}
	}
}

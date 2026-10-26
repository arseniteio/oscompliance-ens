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

func TestGoTypesRoundTrip(t *testing.T) {
	schemas := compileSchemas(t)

	for i, line := range examples(t) {

		var probe Envelope
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatal(err)
		}

		var v any
		switch probe.Fact {
		case IdentityRecordFact:
			v = &IdentityRecord{}
		case IdentitySnapshotFact:
			v = &IdentitySnapshot{}
		case GroupRecordFact:
			v = &GroupRecord{}
		case GroupSnapshotFact:
			v = &GroupSnapshot{}
		case SpecialFileFact:
			v = &SpecialFile{}
		case FileSweepSnapshotFact:
			v = &FileSweepSnapshot{}
		case UmaskSnapshotFact:
			v = &UmaskSnapshot{}
		case SudoGrantFact:
			v = &SudoGrant{}
		case SudoersSnapshotFact:
			v = &SudoersSnapshot{}
		case ConfigFileFact:
			v = &ConfigFile{}
		case ConfigSnapshotFact:
			v = &ConfigSnapshot{}
		case PAMRuleFact:
			v = &PAMRule{}
		case PAMSnapshotFact:
			v = &PAMSnapshot{}
		case AuthLogProbeFact:
			v = &AuthLogProbe{}
		case AgentPassFact:
			v = &AgentPass{}
		case ListeningSocketFact:
			v = &ListeningSocket{}
		case ListeningSnapshotFact:
			v = &ListeningSnapshot{}
		case ServiceLogFact:
			v = &ServiceLog{}
		case ServiceLogSnapshotFact:
			v = &ServiceLogSnapshot{}
		case WazuhAgentConfigFact:
			v = &WazuhAgentConfig{}
		case ACLRecordFact:
			v = &ACLRecord{}
		case ACLSnapshotFact:
			v = &ACLSnapshot{}
		case AuditWatchSnapshotFact:
			v = &AuditWatchSnapshot{}
		case FirewallSnapshotFact:
			v = &FirewallSnapshot{}
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

	const identityRead = `{"oscompliance":"1","fact":"identity_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","passwd_path":"/etc/passwd","passwd_status":"read","shadow_path":"/etc/shadow","shadow_status":"read","records_emitted":2,"sshd_status":"read","authorized_keys_files":[".ssh/authorized_keys"]}`
	const shadowUnread = `{"oscompliance":"1","fact":"identity_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","passwd_path":"/etc/passwd","passwd_status":"read","shadow_path":"/etc/shadow","shadow_status":"unreadable","shadow_error":"denied","sshd_status":"absent"}`
	const identityRecord = `{"oscompliance":"1","fact":"identity_record","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","account_name":"a","uid":1000,"gid":1000,"shell":"/bin/bash","password_state":"set"}`

	const groupRead = `{"oscompliance":"1","fact":"group_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","group_path":"/etc/group","group_status":"read","records_emitted":1}`
	const groupUnread = `{"oscompliance":"1","fact":"group_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","group_path":"/etc/group","group_status":"unreadable","group_error":"denied"}`
	const groupRecord = `{"oscompliance":"1","fact":"group_record","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","group_name":"sudo","gid":27,"members":["a"]}`

	const specialFile = `{"oscompliance":"1","fact":"special_file","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","path":"/usr/bin/sudo","kind":"file","mode":"4755","uid":0,"gid":0,"suid":true,"sgid":false,"sticky":false,"world_writable":false,"no_owner":false,"no_group":false}`
	const sweepSnapshot = `{"oscompliance":"1","fact":"file_sweep_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","roots":["/"],"status":"complete","unreadable":0,"records_emitted":1}`
	const umaskSnapshot = `{"oscompliance":"1","fact":"umask_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","sources":[{"path":"/etc/login.defs","status":"read","umasks":["022"]}]}`
	const sudoGrant = `{"oscompliance":"1","fact":"sudo_grant","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","subject_kind":"group","subject":"sudo","file":"/etc/sudoers","line":50}`
	const sudoersSnapshot = `{"oscompliance":"1","fact":"sudoers_snapshot","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","files":[{"path":"/etc/sudoers","status":"read"}],"status":"read","blind_spots":0,"records_emitted":1}`

	const configFile = `{"oscompliance":"1","fact":"config_file","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","source":"/etc/login.defs","kind":"file","status":"read","entries":[{"key":"PASS_MAX_DAYS","value":"90","line":1}]}`
	const pamRule = `{"oscompliance":"1","fact":"pam_rule","ts":"2026-10-21T14:00:00Z","host":"h","agent_version":"x","run_id":"5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10","service":"sshd","position":0,"type":"auth","control":"required","module":"pam_unix.so","args":[],"file":"/etc/pam.d/common-auth","line":1}`

	cases := []struct {
		name string
		base string
		edit func(map[string]any)
	}{
		{"verdict field", identityRead, func(m map[string]any) { m["estado"] = "CUMPLE" }},
		{"evidence id", identityRecord, func(m map[string]any) { m["evidence_id"] = "EV-01" }},
		{"ts not in UTC", identityRead, func(m map[string]any) { m["ts"] = "2026-10-21T14:00:00+02:00" }},
		{"run_id not a UUID", identityRecord, func(m map[string]any) { m["run_id"] = "x" }},
		{"wrong envelope version", groupRecord, func(m map[string]any) { m["oscompliance"] = "2" }},
		{"identity: records with shadow unread", shadowUnread, func(m map[string]any) { m["records_emitted"] = 0 }},
		{"identity: shadow unread without error", shadowUnread, func(m map[string]any) { delete(m, "shadow_error") }},
		{"identity: error on a read passwd", identityRead, func(m map[string]any) { m["passwd_error"] = "x" }},
		{"identity: both read without records_emitted", identityRead, func(m map[string]any) { delete(m, "records_emitted") }},
		{"identity: password hash", identityRecord, func(m map[string]any) { m["password_hash"] = "$6$abc" }},
		{"identity: unknown password_state", identityRecord, func(m map[string]any) { m["password_state"] = "expired" }},
		{"group: records when unread", groupUnread, func(m map[string]any) { m["records_emitted"] = 0 }},
		{"group: read without records_emitted", groupRead, func(m map[string]any) { delete(m, "records_emitted") }},
		{"group: privileged flag", groupRecord, func(m map[string]any) { m["privileged"] = true }},
		{"group: members not a list", groupRecord, func(m map[string]any) { m["members"] = "a,b" }},
		{"identity: sshd read without key files", identityRead, func(m map[string]any) { delete(m, "authorized_keys_files") }},
		{"identity: key files without sshd", shadowUnread, func(m map[string]any) { m["authorized_keys_files"] = []any{".ssh/authorized_keys"} }},
		{"identity: sshd error without message", identityRead, func(m map[string]any) {
			m["sshd_status"] = "error"
			delete(m, "authorized_keys_files")
		}},
		{"identity: no sshd_status", identityRead, func(m map[string]any) { delete(m, "sshd_status") }},
		{"identity: negative key count", identityRecord, func(m map[string]any) { m["authorized_keys"] = -1 }},
		{"identity: the keys themselves", identityRecord, func(m map[string]any) { m["authorized_keys"] = []any{"ssh-ed25519 AAAA"} }},
		{"sweep: mode without leading digit", specialFile, func(m map[string]any) { m["mode"] = "755" }},
		{"sweep: unknown kind", specialFile, func(m map[string]any) { m["kind"] = "symlink" }},
		{"sweep: error without reason", sweepSnapshot, func(m map[string]any) { m["status"] = "error" }},
		{"sweep: reason without error", sweepSnapshot, func(m map[string]any) { m["sweep_error"] = "x" }},
		{"umask: not octal", umaskSnapshot, func(m map[string]any) {
			m["sources"] = []any{map[string]any{"path": "/etc/profile", "status": "read", "umasks": []any{"0o22"}}}
		}},
		{"sudo: unknown subject kind", sudoGrant, func(m map[string]any) { m["subject_kind"] = "netgroup" }},
		{"sudo: negative blind spots", sudoersSnapshot, func(m map[string]any) { m["blind_spots"] = -1 }},
		{"config: unreadable without error", configFile, func(m map[string]any) { m["status"] = "unreadable" }},
		{"config: entries as an object", configFile, func(m map[string]any) { m["entries"] = map[string]any{"loglevel": "INFO"} }},
		{"pam: unknown type", pamRule, func(m map[string]any) { m["type"] = "authz" }},
		{"pam: missing module", pamRule, func(m map[string]any) { delete(m, "module") }},
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

	for _, base := range []string{identityRead, shadowUnread, identityRecord, groupRead, groupUnread, groupRecord, specialFile, sweepSnapshot, umaskSnapshot, sudoGrant, sudoersSnapshot, configFile, pamRule} {
		if err := validate(schemas, []byte(base)); err != nil {
			t.Errorf("base rejected: %v", err)
		}
	}
}

var wazuhReserved = []string{
	"YARA", "audit", "aws", "azureSignInStatus", "cis", "docker", "gcp", "github",
	"hardware", "ms-graph", "netinfo", "office365", "os", "oscap", "osquery",
	"parameters", "port", "process", "program", "sca", "virustotal", "vulnerability",
	"timestamp", "user",
}

func TestFieldsAvoidWazuhTemplate(t *testing.T) {

	files, err := filepath.Glob(filepath.Join(schemaDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range files {

		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}

		var s struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}

		for _, name := range wazuhReserved {
			if _, taken := s.Properties[name]; taken {
				t.Errorf("%s: field %q collides with the Wazuh alerts template", filepath.Base(f), name)
			}
		}
	}
}

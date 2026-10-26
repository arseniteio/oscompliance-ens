package opacc1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

const groupFixture = `root:x:0:
sudo:x:27:ubuntu,jperez.adm
adm:x:4:syslog, ubuntu ,
broken line
:x:5:a
neg:x:-1:a
`

func collectEV06(t *testing.T, content string, create bool) []map[string]any {
	t.Helper()

	path := filepath.Join(t.TempDir(), "group")
	if create {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	e := emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")
	if err := CollectEV06(e, EV06Config{GroupPath: path}); err != nil {
		t.Fatal(err)
	}

	var facts []map[string]any
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		var f map[string]any
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		facts = append(facts, f)
	}
	return facts
}

func TestCollectEV06(t *testing.T) {
	facts := collectEV06(t, groupFixture, true)

	if len(facts) != 4 {
		t.Fatalf("want 3 records and 1 snapshot, got %d: %v", len(facts), facts)
	}

	want := []struct {
		name    string
		members string
	}{
		{"root", `[]`},
		{"sudo", `["ubuntu","jperez.adm"]`},
		{"adm", `["syslog","ubuntu"]`},
	}
	for i, w := range want {
		members, _ := json.Marshal(facts[i]["members"])
		if facts[i]["fact"] != "group_record" || facts[i]["group_name"] != w.name || string(members) != w.members {
			t.Errorf("record %d: got %v, want %s %s", i, facts[i], w.name, w.members)
		}
	}

	s := facts[3]
	if s["fact"] != "group_snapshot" || s["group_status"] != "read" || s["records_emitted"] != float64(3) || s["group_error"] != nil {
		t.Errorf("snapshot: %v", s)
	}
}

func TestCollectEV06NotRead(t *testing.T) {
	cases := []struct {
		name    string
		content string
		create  bool
		status  string
	}{
		{"missing file", "", false, "unreadable"},
		{"no GID 0", "sudo:x:27:ubuntu\n", true, "implausible"},
	}

	for _, c := range cases {
		facts := collectEV06(t, c.content, c.create)
		if len(facts) != 1 || facts[0]["group_status"] != c.status || facts[0]["group_error"] == nil || facts[0]["records_emitted"] != nil {
			t.Errorf("%s: %v", c.name, facts)
		}
	}
}

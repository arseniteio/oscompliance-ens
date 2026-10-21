package opacc1

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
)

// Remove the t.Skip lines once readShadow, passwordState and accountExpires
// are written.
const ev02Pending = "EV-02 shadow functions not written yet"

func TestPasswordState(t *testing.T) {
	t.Skip(ev02Pending)

	cases := []struct {
		field string
		want  string
	}{
		{"", "empty"},
		{"!", "locked"},
		{"!!", "locked"},
		{"*", "locked"},
		{"!$6$salt$hash", "locked"},
		{"$6$salt$hash", "set"},
		{"$y$j9T$salt$hash", "set"},
		{"x", "other"},
	}

	for _, c := range cases {
		if got := passwordState(c.field); got != c.want {
			t.Errorf("passwordState(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

func TestAccountExpires(t *testing.T) {
	t.Skip(ev02Pending)

	cases := []struct {
		field string
		want  string
	}{
		{"", ""},
		{"0", "1970-01-01"},
		{"1", "1970-01-02"},
		{"20634", "2026-06-30"},
		{"abc", ""},
		{"-1", ""},
	}

	for _, c := range cases {
		if got := accountExpires(c.field); got != c.want {
			t.Errorf("accountExpires(%q) = %q, want %q", c.field, got, c.want)
		}
	}
}

const shadowFixture = `root:!:20000:0:99999:7:::
daemon:*:20000:0:99999:7:::
alice:$6$salt$hash:20000:0:99999:7::20634:
bob::20000:0:99999:7:::
broken line
:$6$x:20000:0:99999:7:::
alice:!:20000:0:99999:7:::
`

func TestReadShadow(t *testing.T) {
	t.Skip(ev02Pending)

	path := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(path, []byte(shadowFixture), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readShadow(path)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]shadowEntry{
		"root":   {passwordState: "locked"},
		"daemon": {passwordState: "locked"},
		"alice":  {passwordState: "set", accountExpires: "2026-06-30"}, // first line wins
		"bob":    {passwordState: "empty"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %v, want %d", len(got), got, len(want))
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %+v, want %+v", name, got[name], w)
		}
	}

	if _, err := readShadow(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file: want an error")
	}
}

// collectEV02 runs CollectEV02 over passwd and shadow contents. An empty
// shadow argument means the shadow file does not exist.
func collectEV02(t *testing.T, passwd, shadow string) []map[string]any {
	t.Helper()

	dir := t.TempDir()
	passwdPath := filepath.Join(dir, "passwd")
	shadowPath := filepath.Join(dir, "shadow")
	if err := os.WriteFile(passwdPath, []byte(passwd), 0o600); err != nil {
		t.Fatal(err)
	}
	if shadow != "" {
		if err := os.WriteFile(shadowPath, []byte(shadow), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	e := emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")
	if err := CollectEV02(e, EV02Config{PasswdPath: passwdPath, ShadowPath: shadowPath}); err != nil {
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

func TestCollectEV02(t *testing.T) {
	t.Skip(ev02Pending)

	passwd := "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ncarol:x:1001:1001::/home/carol:/bin/bash\n"

	facts := collectEV02(t, passwd, shadowFixture)

	if len(facts) != 4 {
		t.Fatalf("want 3 records and 1 snapshot, got %d: %v", len(facts), facts)
	}
	want := []struct{ name, state, expires string }{
		{"root", "locked", ""},
		{"alice", "set", "2026-06-30"},
		{"carol", "missing", ""}, // in passwd, not in shadow
	}
	for i, w := range want {
		f := facts[i]
		expires, _ := f["account_expires"].(string)
		if f["fact"] != "identity_record" || f["account_name"] != w.name || f["password_state"] != w.state || expires != w.expires {
			t.Errorf("record %d: got %v, want %+v", i, f, w)
		}
	}
	s := facts[3]
	if s["fact"] != "identity_snapshot" || s["passwd_status"] != "read" || s["shadow_status"] != "read" || s["records_emitted"] != float64(3) {
		t.Errorf("snapshot: %v", s)
	}

	// Shadow missing: only the snapshot, with the error and no counter.
	facts = collectEV02(t, passwd, "")
	if len(facts) != 1 || facts[0]["shadow_status"] != "unreadable" || facts[0]["shadow_error"] == nil || facts[0]["records_emitted"] != nil {
		t.Errorf("shadow missing: %v", facts)
	}
}

// Does not depend on the shadow functions: passwd fails before shadow is read.
func TestCollectEV02PasswdNotRead(t *testing.T) {
	facts := collectEV02(t, "alice:x:1000:1000::/home/alice:/bin/bash\n", "")

	if len(facts) != 1 {
		t.Fatalf("want only the snapshot, got %v", facts)
	}
	s := facts[0]
	if s["passwd_status"] != "implausible" || s["shadow_status"] != "unreadable" || s["shadow_error"] == nil || s["records_emitted"] != nil {
		t.Errorf("snapshot: %v", s)
	}
}

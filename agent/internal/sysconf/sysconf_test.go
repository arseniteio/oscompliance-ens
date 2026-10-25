package sysconf

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

func run(t *testing.T, collect func(*emit.Emitter) error) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	if err := collect(emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")); err != nil {
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

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseEntries(t *testing.T) {

	in := `# comment
PASS_MAX_DAYS	90
ENV_PATH PATH=/usr/bin:/bin
minlen = 12
dictcheck=1
enforce_for_root
[Journal]
Storage=none
Match User backup
	PasswordAuthentication yes
`
	got, err := parseEntries(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}

	want := []fact.ConfigEntry{
		{Key: "PASS_MAX_DAYS", Value: "90", Line: 2},
		{Key: "ENV_PATH", Value: "PATH=/usr/bin:/bin", Line: 3},
		{Key: "minlen", Value: "12", Line: 4},
		{Key: "dictcheck", Value: "1", Line: 5},
		{Key: "enforce_for_root", Value: "", Line: 6},
		{Key: "Storage", Value: "none", Line: 8, Section: "Journal"},
		{Key: "Match", Value: "User backup", Line: 9},
		{Key: "PasswordAuthentication", Value: "yes", Line: 10, Section: "Match User backup"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCollectConfig(t *testing.T) {

	dir := t.TempDir()
	write(t, filepath.Join(dir, "login.defs"), "PASS_MAX_DAYS 99999\n")
	write(t, filepath.Join(dir, "pwquality.conf.d", "b.conf"), "minlen = 14\n")
	write(t, filepath.Join(dir, "pwquality.conf.d", "a.conf"), "minlen = 10\n")

	facts := run(t, func(e *emit.Emitter) error {
		return CollectConfig(e, ConfigConfig{Files: []string{
			filepath.Join(dir, "login.defs"),
			filepath.Join(dir, "faillock.conf"),
			filepath.Join(dir, "pwquality.conf.d", "*.conf"),
		}})
	})

	if len(facts) != 5 {
		t.Fatalf("got %d facts, want 4 sources and the snapshot", len(facts))
	}

	if facts[1]["status"] != "absent" {
		t.Errorf("missing faillock.conf: got %v", facts[1]["status"])
	}

	// Drop-ins in the order programs read them: a.conf before b.conf.
	if !strings.HasSuffix(facts[2]["source"].(string), "a.conf") || !strings.HasSuffix(facts[3]["source"].(string), "b.conf") {
		t.Errorf("drop-in order: %v, %v", facts[2]["source"], facts[3]["source"])
	}

	if facts[4]["fact"] != "config_snapshot" || facts[4]["records_emitted"] != 4.0 {
		t.Errorf("snapshot: %v", facts[4])
	}
}

func TestCollectPAM(t *testing.T) {

	dir := t.TempDir()

	// Debian style: @include.
	write(t, filepath.Join(dir, "sshd"), "# sshd\n@include common-auth\naccount required pam_nologin.so\n")
	write(t, filepath.Join(dir, "common-auth"), `auth	[success=1 default=ignore]	pam_unix.so nullok
auth requisite pam_deny.so # no fallback
auth required /lib/security/pam_faillock.so authfail \
	deny=3 unlock_time=0
`)

	// RHEL style: type include and substack, only that type is taken.
	write(t, filepath.Join(dir, "login"), "auth substack system-auth\npassword include system-auth\n")
	write(t, filepath.Join(dir, "system-auth"), "auth required pam_env.so\naccount required pam_unix.so\npassword requisite pam_pwquality.so minlen=12\n-session optional pam_systemd.so\n")

	// A loop and a missing include are problems, not failures.
	write(t, filepath.Join(dir, "su"), "@include su\n@include missing\n")

	facts := run(t, func(e *emit.Emitter) error {
		return CollectPAM(e, PAMConfig{Dir: dir, Services: []string{"sshd", "login", "su", "sudo"}})
	})

	var rules []map[string]any
	for _, f := range facts[:len(facts)-1] {
		rules = append(rules, f)
	}
	snapshot := facts[len(facts)-1]

	type rule struct{ service, kind, control, module string }
	want := []rule{
		{"sshd", "auth", "[success=1 default=ignore]", "pam_unix.so"},
		{"sshd", "auth", "requisite", "pam_deny.so"},
		{"sshd", "auth", "required", "pam_faillock.so"},
		{"sshd", "account", "required", "pam_nologin.so"},
		{"login", "auth", "required", "pam_env.so"},
		{"login", "password", "requisite", "pam_pwquality.so"},
	}

	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d: %v", len(rules), len(want), rules)
	}

	for i, w := range want {
		r := rules[i]
		if r["service"] != w.service || r["type"] != w.kind || r["control"] != w.control || r["module"] != w.module {
			t.Errorf("rule %d: got %v %v %v %v, want %v", i, r["service"], r["type"], r["control"], r["module"], w)
		}
	}

	// The continuation is joined and the include chain recorded.
	faillock := rules[2]
	if args := faillock["args"].([]any); len(args) != 3 || args[1] != "deny=3" {
		t.Errorf("faillock args: %v", faillock["args"])
	}
	if via := faillock["via"].([]any); len(via) != 1 || via[0] != filepath.Join(dir, "sshd") || faillock["line"] != 3.0 {
		t.Errorf("faillock via/line: %v %v", faillock["via"], faillock["line"])
	}
	if rules[1]["position"] != 1.0 || rules[4]["position"] != 0.0 {
		t.Errorf("positions: %v %v", rules[1]["position"], rules[4]["position"])
	}

	services := snapshot["services"].([]any)
	if len(services) != 3 || snapshot["records_emitted"] != 6.0 {
		t.Errorf("snapshot: %v", snapshot)
	}
	if problems := snapshot["problems"].([]any); len(problems) != 2 {
		t.Errorf("problems: %v", problems)
	}

	// Types keeps the stacks asked for, includes still followed.
	facts = run(t, func(e *emit.Emitter) error {
		return CollectPAM(e, PAMConfig{Dir: dir, Services: []string{"sshd"}, Types: []string{"account"}})
	})
	if len(facts) != 2 || facts[0]["module"] != "pam_nologin.so" {
		t.Errorf("account only: %v", facts)
	}
}

func TestCollectPAMWithoutDir(t *testing.T) {

	facts := run(t, func(e *emit.Emitter) error {
		return CollectPAM(e, PAMConfig{Dir: filepath.Join(t.TempDir(), "pam.d"), Services: DefaultPAMServices})
	})

	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("got %v", facts)
	}
}

func TestParseHexAddress(t *testing.T) {

	for in, want := range map[string]string{
		"0100007F:0016":                         "127.0.0.1:22",
		"00000000:0016":                         "0.0.0.0:22",
		"050AA8C0:01BB":                         "192.168.10.5:443",
		"00000000000000000000000000000000:0016": ":::22",
		"000080FE000000000000000001000000:0035": "fe80::1:53",
	} {
		ip, port, err := parseHexAddress(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := ip.String() + ":" + strconv.Itoa(port); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestCollectListening(t *testing.T) {

	proc := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	write(t, filepath.Join(proc, "net/tcp"), header+
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0 100 0 0 10 0\n"+
		"   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 100 0 0 10 0\n"+
		"   2: 050AA8C0:0016 0B0AA8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0 100 0 0 10 0\n")
	write(t, filepath.Join(proc, "net/udp"), header+
		"   0: 00000000:04AA 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 2001 2 0\n"+
		"   1: 050AA8C0:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 2002 2 0\n")

	// pid 812 is sshd and holds socket 1001.
	write(t, filepath.Join(proc, "812/comm"), "sshd\n")
	write(t, filepath.Join(proc, "812/cgroup"), "0::/system.slice/ssh.service\n")
	if err := os.MkdirAll(filepath.Join(proc, "812/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[1001]", filepath.Join(proc, "812/fd/3")); err != nil {
		t.Fatal(err)
	}

	facts := run(t, func(e *emit.Emitter) error {
		return CollectListening(e, ListenConfig{Proc: proc, Addresses: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}, &net.IPNet{IP: net.ParseIP("192.168.10.5"), Mask: net.CIDRMask(24, 32)}}, nil
		}})
	})

	if len(facts) != 3 {
		t.Fatalf("want 2 sockets and the snapshot, got %v", facts)
	}

	ssh, vpn, snapshot := facts[0], facts[1], facts[2]

	if ssh["local_address"] != "0.0.0.0" || ssh["local_port"] != 22.0 || ssh["process_name"] != "sshd" || ssh["unit"] != "ssh.service" || ssh["process_id"] != 812.0 {
		t.Errorf("ssh: %v", ssh)
	}
	if vpn["protocol"] != "udp" || vpn["local_port"] != 1194.0 || vpn["process_id"] != nil {
		t.Errorf("udp: %v", vpn)
	}
	if snapshot["records_emitted"] != 2.0 || snapshot["systemd"] != "absent" || snapshot["processes_matched"] != true {
		t.Errorf("snapshot: %v", snapshot)
	}
	if addrs := snapshot["addresses"].([]any); len(addrs) != 1 || addrs[0] != "192.168.10.5" {
		t.Errorf("addresses: %v", addrs)
	}
}

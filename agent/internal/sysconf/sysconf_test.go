package sysconf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
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
	got, err := parseEntries(strings.NewReader(in), false)
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
	if args := faillock["args"].([]any); len(args) != 2 || args[0] != "deny=3" {
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

func TestCollectServiceLogs(t *testing.T) {

	dir := t.TempDir()
	sede := filepath.Join(dir, "sede", "auth.json")
	write(t, sede, `{"ts":"2026-10-25T08:00:00Z","tipo":"autenticacion","usuario":"c1"}`+"\n")

	// The rotated copy, compressed, holds older lines.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("not json\n" + `{"ts":"2026-09-01T07:30:00+02:00","tipo":"autenticacion","usuario":"c0"}` + "\n"))
	zw.Close()
	write(t, sede+".1.gz", gz.String())
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(sede+".1.gz", old, old); err != nil {
		t.Fatal(err)
	}

	write(t, filepath.Join(dir, "client.keys"), "001 lab-agent-01 any 0123\n")
	write(t, filepath.Join(dir, "agent.conf"), `<agent_config>
  <!-- every agent of the group -->
  <localfile><log_format>json</log_format><location>/var/log/other.json</location></localfile>
</agent_config>
<agent_config name="lab-agent-01">
  <localfile>
    <log_format>json</log_format>
    <location>`+sede+`</location>
    <label key="oscompliance_service">sede</label>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>`+filepath.Join(dir, "api.json")+`</location>
    <label key="oscompliance_service">api</label>
  </localfile>
</agent_config>
<agent_config name="someone-else">
  <localfile><location>/x</location><label key="oscompliance_service">x</label></localfile>
</agent_config>
`)

	facts := run(t, func(e *emit.Emitter) error {
		return CollectServiceLogs(e, ServiceLogConfig{SharedConf: filepath.Join(dir, "agent.conf"), ClientKeys: filepath.Join(dir, "client.keys")})
	})

	if len(facts) != 3 {
		t.Fatalf("want sede, api and the snapshot: %v", facts)
	}

	s, api, snap := facts[0], facts[1], facts[2]

	if s["service"] != "sede" || s["status"] != "read" || s["earliest_event"] != "2026-09-01T05:30:00Z" || len(s["rotated"].([]any)) != 1 {
		t.Errorf("sede: %v", s)
	}
	if api["status"] != "absent" {
		t.Errorf("api: %v", api)
	}
	if snap["agent_name"] != "lab-agent-01" || snap["records_emitted"] != 2.0 {
		t.Errorf("snapshot: %v", snap)
	}

	// Not enrolled in a group: no shared configuration.
	facts = run(t, func(e *emit.Emitter) error {
		return CollectServiceLogs(e, ServiceLogConfig{SharedConf: filepath.Join(dir, "none.conf")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("no config: %v", facts)
	}
}

func TestCollectWazuhConfig(t *testing.T) {

	dir := t.TempDir()
	write(t, filepath.Join(dir, "client.keys"), "001 lab-agent-01 any 0123\n")
	write(t, filepath.Join(dir, "ossec.conf"), `<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <ignore>/etc/mtab</ignore>
  </syscheck>
  <localfile><log_format>syslog</log_format><location>/var/log/dpkg.log</location></localfile>
</ossec_config>
`)
	write(t, filepath.Join(dir, "agent.conf"), `<agent_config>
  <syscheck><directories realtime="yes">/srv/datos</directories></syscheck>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
</agent_config>
<agent_config name="other"><syscheck><disabled>yes</disabled></syscheck></agent_config>
`)

	facts := run(t, func(e *emit.Emitter) error {
		return CollectWazuhConfig(e, WazuhConfig{OssecConf: filepath.Join(dir, "ossec.conf"), SharedConf: filepath.Join(dir, "agent.conf"), ClientKeys: filepath.Join(dir, "client.keys")})
	})

	c := facts[0]
	dirs := c["directories"].([]any)
	if c["status"] != "read" || c["syscheck_disabled"] != false || c["syscheck_frequency"] != 43200.0 || len(dirs) != 4 {
		t.Fatalf("config: %v", c)
	}
	if last := dirs[3].(map[string]any); last["path"] != "/srv/datos" || last["realtime"] != true {
		t.Errorf("shared directory: %v", last)
	}
	if lf := c["localfiles"].([]any); len(lf) != 2 || lf[1].(map[string]any)["format"] != "audit" {
		t.Errorf("localfiles: %v", lf)
	}

	facts = run(t, func(e *emit.Emitter) error {
		return CollectWazuhConfig(e, WazuhConfig{OssecConf: filepath.Join(dir, "none")})
	})
	if facts[0]["status"] != "absent" {
		t.Errorf("no agent: %v", facts[0])
	}
}

func TestCollectACL(t *testing.T) {

	dir := t.TempDir()
	datos := filepath.Join(dir, "datos")
	if err := os.Mkdir(datos, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(datos, 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "oscompliance.json"), `{"acl_paths":["`+datos+`","`+filepath.Join(dir, "missing")+`"]}`)

	facts := run(t, func(e *emit.Emitter) error {
		return CollectACL(e, ACLConfig{SharedPaths: filepath.Join(dir, "oscompliance.json")})
	})

	if len(facts) != 3 || facts[0]["mode"] != "0750" || facts[0]["acl"] == nil || facts[1]["status"] != "absent" || facts[2]["records_emitted"] != 2.0 {
		t.Errorf("acl: %v", facts)
	}

	facts = run(t, func(e *emit.Emitter) error {
		return CollectACL(e, ACLConfig{SharedPaths: filepath.Join(dir, "none.json")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("no shared file: %v", facts)
	}
}

func TestParseACL(t *testing.T) {

	entry := func(tag, perm uint16, id uint32) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b, tag)
		binary.LittleEndian.PutUint16(b[2:], perm)
		binary.LittleEndian.PutUint32(b[4:], id)
		return b
	}

	data := []byte{2, 0, 0, 0}
	data = append(data, entry(aclUserObj, 7, 0)...)
	data = append(data, entry(aclUser, 5, 4242424)...)
	data = append(data, entry(aclGroupObj, 5, 0)...)
	data = append(data, entry(aclMask, 5, 0)...)
	data = append(data, entry(aclOther, 0, 0)...)

	got, err := parseACL(data, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "u:4242424:r-x,m::r-x" {
		t.Errorf("access ACL: %v", got)
	}

	got, _ = parseACL(data, "d:", true)
	if len(got) != 5 || got[0] != "d:u::rwx" || got[4] != "d:o::---" {
		t.Errorf("default ACL: %v", got)
	}

	if _, err := parseACL([]byte{1, 0, 0, 0}, "", false); err == nil {
		t.Error("bad version must fail")
	}
}

func TestParseWatches(t *testing.T) {

	got := parseWatches(`-w /srv/datos -p r -k oscompliance_read
-w /etc/passwd -p wa -k identity
-a always,exit -F arch=b64 -S all -F dir=/srv/app -F perm=w -F key=oscompliance_write
`)
	if strings.Join(got, ",") != "/srv/datos oscompliance_read,/srv/app oscompliance_write" {
		t.Errorf("watches: %v", got)
	}

	if !auditRunning("enabled 1\nfailure 1\npid 812\n") || auditRunning("enabled 1\npid 0\n") || auditRunning("enabled 0\npid 9\n") {
		t.Error("auditctl -s reading")
	}
}

func TestParseSambaEntries(t *testing.T) {

	got, err := parseEntries(strings.NewReader("[global]\n  map to guest = Bad User\n[public]\n  guest   ok = yes\n; comment\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != "map to guest" || got[1].Key != "guest ok" || got[1].Value != "yes" || got[1].Section != "public" {
		t.Errorf("samba: %+v", got)
	}
}

func TestFirewallParsing(t *testing.T) {

	chains, err := nftChains(`{"nftables":[{"metainfo":{"version":"1.0.9"}},
{"chain":{"family":"inet","table":"filter","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
{"chain":{"family":"inet","table":"filter","name":"forward","handle":2,"type":"filter","hook":"forward","prio":0,"policy":"accept"}},
{"chain":{"family":"ip","table":"nat","name":"post","handle":3,"type":"nat","hook":"postrouting","prio":100,"policy":"accept"}},
{"chain":{"family":"inet","table":"filter","name":"user_rules","handle":4}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 2 || chains[0].Policy != "drop" || chains[1].Hook != "forward" {
		t.Errorf("nft: %+v", chains)
	}

	ipt := iptablesChains("-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n", "ip")
	if len(ipt) != 2 || ipt[0].Policy != "accept" || ipt[1].Policy != "drop" {
		t.Errorf("iptables: %+v", ipt)
	}
}

func TestAuditSafety(t *testing.T) {

	for p, ok := range map[string]bool{"/srv/datos": true, "/": false, "/etc": false, "relative": false, "/srv/../etc": false, "/srv/a b": false} {
		if (unsafeWatch(p) == "") != ok {
			t.Errorf("%q: %q", p, unsafeWatch(p))
		}
	}

	if n := len(permRules("amd64")); n != 10 {
		t.Errorf("amd64 rules: %d", n)
	}
	for _, r := range permRules("arm64") {
		for _, f := range r {
			if strings.Contains(f, "arch=b32") || strings.HasPrefix(f, "chmod") || strings.HasPrefix(f, "chown") {
				t.Errorf("arm64 rule %v", r)
			}
		}
	}
}

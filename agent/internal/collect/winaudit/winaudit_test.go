package winaudit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

type recorder struct {
	scripts []string
	outputs []string
}

func (r *recorder) run(script string) ([]byte, error) {
	r.scripts = append(r.scripts, script)
	out := r.outputs[0]
	r.outputs = r.outputs[1:]
	return []byte(out), nil
}

func (r *recorder) input(t *testing.T, i int) map[string]any {
	t.Helper()
	_, rest, _ := strings.Cut(r.scripts[i], "FromBase64String('")
	encoded, _, _ := strings.Cut(rest, "'")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("input %s: %v", raw, err)
	}
	return v
}

func config(t *testing.T, shared string) Config {
	t.Helper()
	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "agent.conf"), shared)
	collecttest.Write(t, filepath.Join(dir, "client.keys"), "007 WS01 any key\n")
	return Config{Wazuh: wazuh.AgentConfigPaths{SharedConf: filepath.Join(dir, "agent.conf"), ClientKeys: filepath.Join(dir, "client.keys")}, Managed: filepath.Join(dir, "managed.json"), Guard: filepath.Join(dir, "guard.json")}
}

const shared = `<agent_config>
  <!-- oscompliance {"acl_paths":[],"audit_watches":["C:\\Windows\\System32\\drivers\\etc"],"read_watches":["C:\\ProgramData\\ssh","C:\\Program Files (x86)\\ossec-agent\\client.keys","relative\\path"],"exec_watches":[]} -->
</agent_config>
`

func TestCollectAddsWantedAndRemovesStaleEntries(t *testing.T) {

	cfg := config(t, shared)
	if err := writeJSON(cfg.Managed, Managed{Watches: []Watch{{Path: `C:\old`, Access: "read"}}}); err != nil {
		t.Fatal(err)
	}
	r := &recorder{outputs: []string{`{"loaded":["C:\\ProgramData\\ssh","C:\\Windows\\System32\\drivers\\etc"],"failed":[{"path":"C:\\Program Files (x86)\\ossec-agent\\client.keys","error":"path not found"}],"removed":["C:\\old"]}`}}

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, r.run, cfg, now) })

	in := r.input(t, 0)
	if len(in["set"].([]any)) != 3 || len(in["unset"].([]any)) != 1 {
		t.Errorf("sacl input %v", in)
	}
	s := facts[0]
	if s["auditd"] != "running" || len(s["wanted"].([]any)) != 3 || len(s["read_wanted"].([]any)) != 2 || len(s["failed"].([]any)) != 1 || s["unloaded"].([]any)[0] != `C:\old` {
		t.Errorf("snapshot %v", s)
	}

	var m Managed
	if err := readJSON(cfg.Managed, &m); err != nil || len(m.Watches) != 2 {
		t.Errorf("managed %+v, %v", m, err)
	}
}

func TestSuspendedReadWatchStaysOff(t *testing.T) {
	wanted := []Watch{{Path: `C:\keys`, Access: "read"}, {Path: `C:\conf`, Access: "write"}}
	managed := []Watch{{Path: `C:\keys`, Access: "read"}}
	set, unset := Plan(wanted, managed, map[string]time.Time{`C:\keys`: now.Add(time.Minute), `C:\conf`: now.Add(time.Minute)}, now)
	if len(set) != 1 || set[0].Path != `C:\conf` || len(unset) != 1 || unset[0].Path != `C:\keys` {
		t.Errorf("set %v unset %v", set, unset)
	}
	set, _ = Plan(wanted, managed, map[string]time.Time{`C:\keys`: now}, now)
	if len(set) != 2 {
		t.Errorf("an expired suspension still holds: %v", set)
	}
}

func guardConfig(t *testing.T) GuardConfig {
	t.Helper()
	dir := t.TempDir()
	cfg := GuardConfig{Managed: filepath.Join(dir, "managed.json"), State: filepath.Join(dir, "guard.json"), Limit: 2, Suspend: time.Hour}
	if err := writeJSON(cfg.Managed, Managed{Watches: []Watch{{Path: `C:\ProgramData\ssh`, Access: "read"}, {Path: `C:\ProgramData\ssh\private`, Access: "read"}, {Path: `C:\etc`, Access: "write"}}}); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestGuardForwardsAccessesAndSuspendsAFlood(t *testing.T) {

	cfg := guardConfig(t)
	if err := writeJSON(cfg.State, GuardState{Bookmark: 100, Last: now.Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ev := func(object, mask string) string {
		return `{"time":"2026-11-17T11:59:30.0000000Z","account":"ana","domain":"CORP","object":"` + strings.ReplaceAll(object, `\`, `\\`) + `","mask":"` + mask + `","process":"C:\\Windows\\notepad.exe"}`
	}
	events := []string{ev(`C:\ProgramData\ssh\private\key`, "0x1"), ev(`C:\ProgramData\ssh\private\key`, "0x1"), ev(`C:\ProgramData\ssh\private\key`, "0x1"),
		ev(`C:\ProgramData\SSH\sshd_config`, "0x1"), ev(`C:\etc\hosts`, "0x2"), ev(`C:\Windows\win.ini`, "0x1")}
	r := &recorder{outputs: []string{`{"newest":250,"events":[` + strings.Join(events, ",") + `]}`, `{"loaded":[],"failed":[],"removed":["C:\\ProgramData\\ssh\\private"]}`}}

	var suspended []Suspension
	facts := collecttest.Facts(t, func(e *emit.Emitter) (err error) {
		suspended, err = Guard(e, r.run, cfg, now)
		return err
	})

	if len(facts) != 5 {
		t.Fatalf("%d facts, want the 5 accesses under a watch", len(facts))
	}
	if facts[0]["watch"] != `C:\ProgramData\ssh\private` || facts[0]["access"] != fact.AccessRead || facts[0]["account"] != "ana" {
		t.Errorf("first %v", facts[0])
	}
	if facts[4]["access"] != fact.AccessWrite || facts[4]["watch"] != `C:\etc` {
		t.Errorf("write %v", facts[4])
	}
	if len(suspended) != 1 || suspended[0].Path != `C:\ProgramData\ssh\private` || suspended[0].Reads != 3 {
		t.Errorf("suspended %+v", suspended)
	}
	if r.input(t, 0)["since"] != 100.0 || len(r.input(t, 1)["unset"].([]any)) != 1 {
		t.Errorf("inputs %v %v", r.input(t, 0), r.input(t, 1))
	}

	var state GuardState
	if err := readJSON(cfg.State, &state); err != nil || state.Bookmark != 250 || !state.Suspended[`C:\ProgramData\ssh\private`].Equal(now.Add(time.Hour)) {
		t.Errorf("state %+v, %v", state, err)
	}
}

func TestGuardFirstRunOnlyTakesTheBookmark(t *testing.T) {
	cfg := guardConfig(t)
	r := &recorder{outputs: []string{`{"newest":9000,"events":[]}`}}
	var buf bytes.Buffer
	if _, err := Guard(emit.New(&buf, "h", "test", "run"), r.run, cfg, now); err != nil {
		t.Fatal(err)
	}
	var state GuardState
	if err := readJSON(cfg.State, &state); err != nil || state.Bookmark != 9000 || buf.Len() != 0 {
		t.Errorf("state %+v, output %q, %v", state, buf.String(), err)
	}
}

func TestAbsolute(t *testing.T) {
	for p, want := range map[string]bool{`C:\x`: true, `d:/y`: true, `\\server\share`: false, `x\y`: false, `/etc`: false, `C:`: false} {
		if Absolute(p) != want {
			t.Errorf("Absolute(%q) != %v", p, want)
		}
	}
}

func TestGuardKeepsItsPlaceWhenTheBatchIsFull(t *testing.T) {

	cfg := guardConfig(t)
	if err := writeJSON(cfg.State, GuardState{Bookmark: 10}); err != nil {
		t.Fatal(err)
	}
	events := make([]string, MaxEvents)
	for i := range events {
		events[i] = `{"record":` + strconv.Itoa(11+i) + `,"time":"2026-11-17T11:59:30Z","account":"x","object":"C:\\other","mask":"0x1"}`
	}
	r := &recorder{outputs: []string{`{"newest":99999,"events":[` + strings.Join(events, ",") + `]}`}}
	var buf bytes.Buffer
	if _, err := Guard(emit.New(&buf, "h", "test", "run"), r.run, cfg, now); err != nil {
		t.Fatal(err)
	}
	var state GuardState
	if err := readJSON(cfg.State, &state); err != nil || state.Bookmark != int64(10+MaxEvents) {
		t.Errorf("bookmark %d, want %d", state.Bookmark, 10+MaxEvents)
	}
}

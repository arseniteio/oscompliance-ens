package wazuh

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
)

func TestCollectServiceLogs(t *testing.T) {

	dir := t.TempDir()
	sede := filepath.Join(dir, "sede", "auth.json")
	collecttest.Write(t, sede, `{"ts":"2026-10-25T08:00:00Z","tipo":"autenticacion","usuario":"c1"}`+"\n")

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("not json\n" + `{"ts":"2026-09-01T07:30:00+02:00","tipo":"autenticacion","usuario":"c0"}` + "\n"))
	zw.Close()
	collecttest.Write(t, sede+".1.gz", gz.String())
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(sede+".1.gz", old, old); err != nil {
		t.Fatal(err)
	}

	collecttest.Write(t, filepath.Join(dir, "client.keys"), "001 lab-agent-01 any 0123\n")
	collecttest.Write(t, filepath.Join(dir, "agent.conf"), `<agent_config>
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

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
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

	facts = collecttest.Facts(t, func(e *emit.Emitter) error {
		return CollectServiceLogs(e, ServiceLogConfig{SharedConf: filepath.Join(dir, "none.conf")})
	})
	if len(facts) != 1 || facts[0]["status"] != "absent" {
		t.Errorf("no config: %v", facts)
	}
}

func TestCollectWazuhConfig(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "client.keys"), "001 lab-agent-01 any 0123\n")
	collecttest.Write(t, filepath.Join(dir, "ossec.conf"), `<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <ignore>/etc/mtab</ignore>
  </syscheck>
  <localfile><log_format>syslog</log_format><location>/var/log/dpkg.log</location></localfile>
  <wodle name="syscollector"><disabled>no</disabled><interval>1h</interval><processes>no</processes></wodle>
  <sca><enabled>yes</enabled><interval>12h</interval></sca>
</ossec_config>
`)
	collecttest.Write(t, filepath.Join(dir, "agent.conf"), `<agent_config>
  <syscheck><directories realtime="yes">/srv/datos</directories></syscheck>
  <localfile><log_format>audit</log_format><location>/var/log/audit/audit.log</location></localfile>
</agent_config>
<agent_config><wodle name="syscollector"><interval>12h</interval></wodle><sca><interval>1d</interval></sca></agent_config>
<agent_config name="other"><syscheck><disabled>yes</disabled></syscheck></agent_config>
`)

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return CollectAgentConfig(e, AgentConfigPaths{OssecConf: filepath.Join(dir, "ossec.conf"), SharedConf: filepath.Join(dir, "agent.conf"), ClientKeys: filepath.Join(dir, "client.keys")})
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

	if c["syscollector_disabled"] != false || c["syscollector_interval"] != 43200.0 || fmt.Sprint(c["syscollector_scans"]) != "[hardware os network packages ports]" {
		t.Errorf("syscollector: %v %v %v", c["syscollector_disabled"], c["syscollector_interval"], c["syscollector_scans"])
	}
	if c["sca_disabled"] != false || c["sca_interval"] != 86400.0 {
		t.Errorf("sca: %v %v", c["sca_disabled"], c["sca_interval"])
	}

	facts = collecttest.Facts(t, func(e *emit.Emitter) error {
		return CollectAgentConfig(e, AgentConfigPaths{OssecConf: filepath.Join(dir, "none")})
	})
	if facts[0]["status"] != "absent" {
		t.Errorf("no agent: %v", facts[0])
	}
}

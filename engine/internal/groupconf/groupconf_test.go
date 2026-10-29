package groupconf

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/wazuhapi"
)

func policyOf(t *testing.T, doc string) *params.Config {
	t.Helper()
	var c params.Config
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		t.Fatal(err)
	}
	return &c
}

const fleet = `{
  "scope": {"mode": "group", "groupIds": ["ens"]},
  "controls": [
    {"controlId": "op.acc.2", "parameters": [
      {"id": "P-02", "value": ["/etc/passwd", "/srv/app/config"]},
      {"id": "P-06", "value": ["admin | /srv/datos | r,w"]},
      {"id": "P-08", "value": ["/etc/ssh | 0755 | root"]}
    ]},
    {"controlId": "op.acc.3", "parameters": [
      {"id": "P-03", "value": ["desarrollo | /usr/bin/git | /srv/repos", "operacion | systemctl"]}
    ]},
    {"controlId": "op.acc.4", "parameters": [{"id": "P-07", "value": ["/datos/rrhh | rrhh"]}]},
    {"controlId": "op.acc.5", "parameters": [{"id": "P-02", "value": ["sede | web01 | /var/log/sede/auth.json"]}]},
    {"controlId": "op.exp.2", "parameters": [{"id": "P-08", "value": ["/etc/shadow | 640 | root", "/etc/ssh | 755 | root"]}]}
  ],
  "agents": {"003": {"controls": {"op.acc.2": {"parameters": {"P-08": ["/opt/other | 0700 | root"]}}}}}
}`

func TestForAgent(t *testing.T) {

	m := ForAgent(policyOf(t, fleet), "001", "web01")

	if strings.Join(m.FIM, ",") != "/srv/app/config" {
		t.Errorf("FIM: only what Wazuh does not watch by default: %v", m.FIM)
	}
	if strings.Join(m.Paths.ACL, ",") != "/etc/shadow,/etc/ssh" {
		t.Errorf("ACL: %v", m.Paths.ACL)
	}
	if strings.Join(m.Paths.Exec, ",") != "/usr/bin/git" {
		t.Errorf("exec: binaries of P-03: %v", m.Paths.Exec)
	}
	want := "/datos/rrhh,/etc/audit,/srv/datos,/srv/repos,/var/log/audit,/var/ossec/etc"
	if strings.Join(m.Paths.Audit, ",") != want {
		t.Errorf("audit: %v", m.Paths.Audit)
	}
	if len(m.Services) != 1 || m.Services[0].Log != "/var/log/sede/auth.json" {
		t.Errorf("services of web01: %v", m.Services)
	}
	if len(ForAgent(policyOf(t, fleet), "002", "db01").Services) != 0 {
		t.Error("a service belongs only to the machine its row names")
	}
}

func TestRegion(t *testing.T) {

	policy := policyOf(t, fleet)
	agents := []Agent{
		{Name: "web01", Machine: ForAgent(policy, "001", "web01")},
		{Name: "db01", Machine: ForAgent(policy, "002", "db01")},
		{Name: "odd01", Machine: ForAgent(policy, "003", "odd01")},
	}
	region := Region(agents)

	var root struct {
		Blocks []struct {
			Name     string `xml:"name,attr"`
			Comments string `xml:",comment"`
			Logs     []struct {
				Location string `xml:"location"`
			} `xml:"localfile"`
		} `xml:"agent_config"`
	}
	if err := xml.Unmarshal([]byte("<root>"+region+"</root>"), &root); err != nil {
		t.Fatalf("not XML: %v\n%s", err, region)
	}

	names := []string{}
	for _, b := range root.Blocks {
		names = append(names, b.Name)
	}
	if strings.Join(names, ",") != ",odd01,web01" {
		t.Fatalf("one common block, then only the machines that differ: %v", names)
	}
	if !strings.Contains(root.Blocks[0].Comments, `"acl_paths":["/etc/shadow","/etc/ssh"]`) || len(root.Blocks[0].Logs) != 2 {
		t.Errorf("common block: %s", region)
	}
	if !strings.Contains(root.Blocks[1].Comments, `"/opt/other"`) {
		t.Errorf("odd01 carries its own paths: %s", region)
	}
	if strings.Contains(root.Blocks[2].Comments, "acl_paths") || len(root.Blocks[2].Logs) != 1 {
		t.Errorf("web01 only adds its service log: %s", region)
	}
}

func TestMerge(t *testing.T) {

	admin := "<agent_config>\n  <localfile><location>/var/log/app.log</location></localfile>\n</agent_config>\n"
	first := Region([]Agent{{Name: "a", Machine: Machine{}}})

	once := Merge(admin, first)
	if !strings.HasPrefix(once, admin) || Current(once) != first {
		t.Fatalf("appended after what the administrator wrote:\n%s", once)
	}

	second := Region([]Agent{{Name: "a", Machine: Machine{Paths: Paths{ACL: []string{"/x"}}}}})
	twice := Merge(once, second)
	if !strings.HasPrefix(twice, admin) || Current(twice) != second || strings.Count(twice, begin) != 1 {
		t.Fatalf("the region is replaced, never repeated:\n%s", twice)
	}
}

func TestCommentNeverHoldsDoubleHyphen(t *testing.T) {
	var b strings.Builder
	writePaths(&b, Paths{ACL: []string{"/srv/a--b"}})
	inside := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(b.String()), "<!--"), "-->")
	if strings.Contains(inside, "--") {
		t.Errorf("an XML comment cannot hold --: %s", b.String())
	}
	var p Paths
	body := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(inside), pathsMarker))
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.ACL[0] != "/srv/a--b" {
		t.Errorf("the path survives: %v %v", p, err)
	}
}

type fakeAPI struct {
	agents map[string][]wazuhapi.Agent
	conf   map[string]string
	puts   int
}

func (f *fakeAPI) GroupAgents(_ context.Context, g string) ([]wazuhapi.Agent, error) {
	return f.agents[g], nil
}

func (f *fakeAPI) GroupConfiguration(_ context.Context, g string) (string, error) {
	return f.conf[g], nil
}

func (f *fakeAPI) PutGroupConfiguration(_ context.Context, g, c string) error {
	f.puts++
	f.conf[g] = c
	return nil
}

func TestSync(t *testing.T) {

	policy := policyOf(t, fleet)
	api := &fakeAPI{
		agents: map[string][]wazuhapi.Agent{"ens": {{ID: "001", Name: "web01"}, {ID: "002", Name: "db01"}}},
		conf:   map[string]string{"ens": "<agent_config>\n</agent_config>\n"},
	}
	now := time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)

	planned, err := Sync(context.Background(), api, policy, policy.Groups(), false, now)
	if err != nil || len(planned) != 1 || planned[0].Applied || api.puts != 0 {
		t.Fatalf("without apply nothing is written: %v %v %d", planned, err, api.puts)
	}

	applied, err := Sync(context.Background(), api, policy, policy.Groups(), true, now)
	if err != nil || len(applied) != 1 || !applied[0].Applied || api.puts != 1 {
		t.Fatalf("applied: %v %v %d", applied, err, api.puts)
	}

	api.conf["ens"] = strings.ReplaceAll(api.conf["ens"], "\n", "\n    ")
	again, err := Sync(context.Background(), api, policy, policy.Groups(), true, now)
	if err != nil || len(again) != 0 || api.puts != 1 {
		t.Errorf("nothing changed, nothing written, however the manager indents it: %v %v %d", again, err, api.puts)
	}
}

package winacl

import (
	"path/filepath"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

func TestRecordsForWindowsPaths(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "agent.conf"), `<agent_config><!-- oscompliance {"acl_paths":["C:\\ProgramData\\ssh","/etc/shadow"],"audit_watches":[],"read_watches":[],"exec_watches":[]} --></agent_config>`)
	paths := wazuh.AgentConfigPaths{SharedConf: filepath.Join(dir, "agent.conf"), ClientKeys: filepath.Join(dir, "none")}

	out := `{"records":[{"path":"C:\\ProgramData\\ssh","status":"read","owner":"BUILTIN\\Administrators","acl":["NT AUTHORITY\\SYSTEM:Allow:FullControl"]}]}`
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out), paths) })

	if len(facts) != 2 || facts[0]["owner"] != `BUILTIN\Administrators` || facts[1]["records_emitted"] != 1.0 {
		t.Errorf("got %v", facts)
	}
}

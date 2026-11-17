package winpolicy

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

const sample = `{"secedit":["[Unicode]","Unicode=yes","[System Access]","MinimumPasswordLength = 14","LockoutBadCount = 5","NewAdministratorName = \"Administrator\"","[Event Audit]","AuditLogonEvents = 3","[Privilege Rights]","SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555","[Version]","signature=\"$CHICAGO$\""],
"secedit_error":"",
"auditpol":[{"subcategory":"Inicio de sesión","guid":"{0cce9215-69ae-11d9-bed3-505054503030}","value":"3"}],
"auditpol_error":"",
"registry":[{"path":"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa","exists":true,"values":{"NoLMHash":"1","LmCompatibilityLevel":"5"}},{"path":"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service","exists":false,"values":{}}]}`

func TestPolicySources(t *testing.T) {

	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(sample)) })
	if len(facts) != 5 {
		t.Fatalf("%d facts, want secedit, auditpol, two registry keys and a snapshot", len(facts))
	}

	secedit := facts[0]["entries"].([]any)
	want := []struct{ section, key, value string }{
		{"System Access", "MinimumPasswordLength", "14"},
		{"System Access", "LockoutBadCount", "5"},
		{"System Access", "NewAdministratorName", "Administrator"},
		{"Event Audit", "AuditLogonEvents", "3"},
		{"Privilege Rights", "SeRemoteInteractiveLogonRight", "*S-1-5-32-544,*S-1-5-32-555"},
	}
	if len(secedit) != len(want) {
		t.Fatalf("secedit entries %v", secedit)
	}
	for i, w := range want {
		got := secedit[i].(map[string]any)
		if got["section"] != w.section || got["key"] != w.key || got["value"] != w.value {
			t.Errorf("entry %d = %v, want %+v", i, got, w)
		}
	}

	audit := facts[1]["entries"].([]any)[0].(map[string]any)
	if facts[1]["source"] != "auditpol" || audit["key"] != "0CCE9215-69AE-11D9-BED3-505054503030" || audit["value"] != "3" {
		t.Errorf("auditpol %v", facts[1])
	}

	lsa := facts[2]["entries"].([]any)
	if facts[2]["source"] != `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` || len(lsa) != 2 || lsa[0].(map[string]any)["key"] != "LmCompatibilityLevel" {
		t.Errorf("registry %v", facts[2])
	}
	if facts[3]["status"] != "absent" {
		t.Errorf("missing key %v", facts[3])
	}
	if facts[4]["records_emitted"] != 4.0 {
		t.Errorf("snapshot %v", facts[4])
	}
}

func TestPolicyToolErrors(t *testing.T) {
	out := `{"secedit":[],"secedit_error":"secedit exit 3","auditpol":[],"auditpol_error":"auditpol exit 5","registry":[]}`
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return Collect(e, winps.Static(out)) })
	if facts[0]["status"] != "error" || facts[1]["status"] != "error" || facts[1]["error"] != "auditpol exit 5" {
		t.Errorf("got %v", facts)
	}
}

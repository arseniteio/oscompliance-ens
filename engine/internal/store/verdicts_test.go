package store

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func TestDocumentID(t *testing.T) {
	agent := verdict.Agent{ID: "001", Name: "a"}
	ts := "2026-10-22T15:20:00Z"

	cases := map[string]verdict.Verdict{
		"001/op.acc.1/EV-01/r1":              {Scope: verdict.ScopeEvidence, Agent: agent, Control: "op.acc.1", Evidence: "EV-01", RunID: "r1", Timestamp: ts},
		"001/op.acc.1/EV-03/none":            {Scope: verdict.ScopeEvidence, Agent: agent, Control: "op.acc.1", Evidence: "EV-03", Timestamp: ts},
		"001/op.acc.1/op.acc.1.4/2026-10-22": {Scope: verdict.ScopeRequirement, Agent: agent, Control: "op.acc.1", Requirement: "op.acc.1.4", Timestamp: ts},
		"001/op.acc.1/2026-10-22":            {Scope: verdict.ScopeControl, Agent: agent, Control: "op.acc.1", Timestamp: ts},
		"organization/ENS/2026-10-22":        {Scope: verdict.ScopeOrganization, Agent: verdict.Agent{ID: verdict.OrganizationAgent}, Control: verdict.AllMeasures, Timestamp: ts},
	}

	for want, v := range cases {
		if got := DocumentID(v); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}

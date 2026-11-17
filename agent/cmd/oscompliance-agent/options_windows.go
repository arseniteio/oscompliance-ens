package main

import (
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/audit"
)

const defaultConfigPath = `C:\ProgramData\oscompliance\agent.json`

func defaultOptions() options {
	return options{
		Output:         `C:\ProgramData\oscompliance\facts.ndjson`,
		State:          `C:\ProgramData\oscompliance\state\state.json`,
		Collectors:     append([]string(nil), allCollectors...),
		SweepTimeout:   duration{15 * time.Minute},
		AuditReadLimit: audit.DefaultReadLimit,
		Paths: paths{
			WazuhSharedConf: `C:\Program Files (x86)\ossec-agent\shared\agent.conf`,
			WazuhClientKeys: `C:\Program Files (x86)\ossec-agent\client.keys`,
		},
	}
}

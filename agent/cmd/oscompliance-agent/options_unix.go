//go:build !windows

package main

import (
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/audit"
)

const defaultConfigPath = "/etc/oscompliance/agent.json"

func defaultOptions() options {
	return options{
		Output:         "/var/log/oscompliance/facts.ndjson",
		State:          "/var/lib/oscompliance/state.json",
		Collectors:     slices.DeleteFunc(slices.Clone(allCollectors), func(c string) bool { return c == "sweep" }),
		SweepTimeout:   duration{15 * time.Minute},
		AuditReadLimit: audit.DefaultReadLimit,
		Paths: paths{
			Passwd:          "/etc/passwd",
			Shadow:          "/etc/shadow",
			Group:           "/etc/group",
			SSHD:            "/usr/sbin/sshd",
			Sudoers:         "/etc/sudoers",
			PAMDir:          "/etc/pam.d",
			WazuhSharedConf: "/var/ossec/etc/shared/agent.conf",
			WazuhClientKeys: "/var/ossec/etc/client.keys",
		},
	}
}

//go:build !windows

package wazuh

import (
	"os"
	"syscall"
)

const blockOS = "linux"

var DefaultAgentConfig = AgentConfigPaths{
	OssecConf:  "/var/ossec/etc/ossec.conf",
	SharedConf: "/var/ossec/etc/shared/agent.conf",
	ClientKeys: "/var/ossec/etc/client.keys",
}

func inode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

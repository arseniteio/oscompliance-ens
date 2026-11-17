package wazuh

import "os"

const blockOS = "windows"

var DefaultAgentConfig = AgentConfigPaths{
	OssecConf:  `C:\Program Files (x86)\ossec-agent\ossec.conf`,
	SharedConf: `C:\Program Files (x86)\ossec-agent\shared\agent.conf`,
	ClientKeys: `C:\Program Files (x86)\ossec-agent\client.keys`,
}

func inode(os.FileInfo) uint64 { return 0 }

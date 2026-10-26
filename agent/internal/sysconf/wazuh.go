package sysconf

import (
	"encoding/json"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"
	"io/fs"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// WazuhConfig says where the Wazuh agent keeps its configuration.
type WazuhConfig struct {
	OssecConf  string // /var/ossec/etc/ossec.conf
	SharedConf string // /var/ossec/etc/shared/agent.conf
	ClientKeys string // /var/ossec/etc/client.keys
}

// DefaultWazuhConfig is the layout of a Wazuh agent on Linux.
var DefaultWazuhConfig = WazuhConfig{
	OssecConf:  "/var/ossec/etc/ossec.conf",
	SharedConf: "/var/ossec/etc/shared/agent.conf",
	ClientKeys: "/var/ossec/etc/client.keys",
}

// CollectWazuhConfig emits one wazuh_agent_config: the FIM directories and
// the log files the Wazuh agent watches, ossec.conf first, then the shared
// blocks that apply to it, which the manager sends and which take
// precedence.
func CollectWazuhConfig(e *emit.Emitter, cfg WazuhConfig) error {

	out := fact.WazuhAgentConfig{Envelope: e.Envelope(fact.WazuhAgentConfigFact), Status: fact.SourceRead,
		Directories: []fact.FIMDirectory{}, Localfiles: []fact.AgentLocalfile{}}

	local, err := fsread.ReadFile(cfg.OssecConf)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		out.Status = fact.SourceAbsent
		return e.Emit(out)
	case err != nil:
		out.Status, out.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(out)
	}

	name := agentName(cfg.ClientKeys)

	blocks, err := applicableBlocks(local, "ossec_config", name)
	if err != nil {
		out.Status, out.Error = fact.SourceUnreadable, cfg.OssecConf+": "+err.Error()
		return e.Emit(out)
	}
	add(&out, blocks, cfg.OssecConf)

	// No shared configuration is fine: the agent is in no group.
	if shared, err := fsread.ReadFile(cfg.SharedConf); err == nil {
		blocks, err := applicableBlocks(shared, "agent_config", name)
		if err != nil {
			out.Status, out.Error = fact.SourceUnreadable, cfg.SharedConf+": "+err.Error()
			return e.Emit(out)
		}
		add(&out, blocks, cfg.SharedConf)
	} else if !errors.Is(err, fs.ErrNotExist) {
		out.Status, out.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(out)
	}

	return e.Emit(out)
}

// add merges the sections of the blocks of one file into out.
func add(out *fact.WazuhAgentConfig, blocks []agentConfig, source string) {

	for _, b := range blocks {

		for _, s := range b.Syscheck {

			if d := strings.TrimSpace(s.Disabled); d != "" {
				out.SyscheckDisabled = d == "yes"
			}
			if n, err := strconv.Atoi(strings.TrimSpace(s.Frequency)); err == nil {
				out.SyscheckFrequency = n
			}

			for _, d := range s.Directories {
				for _, p := range strings.Split(d.Paths, ",") {
					if p = strings.TrimSpace(p); p != "" {
						out.Directories = append(out.Directories, fact.FIMDirectory{Path: p, Realtime: d.Realtime == "yes", Whodata: d.Whodata == "yes", Source: source})
					}
				}
			}

			for _, i := range s.Ignore {
				if i = strings.TrimSpace(i); i != "" {
					out.Ignored = append(out.Ignored, i)
				}
			}
		}

		for _, l := range b.Localfiles {
			if loc := strings.TrimSpace(l.Location); loc != "" {
				out.Localfiles = append(out.Localfiles, fact.AgentLocalfile{Location: loc, Format: strings.TrimSpace(l.Format), Source: source})
			}
		}
	}
}

// SharedPaths is the oscompliance.json the manager puts in the group's
// shared files: the paths a control watches that come from a parameter.
// Wazuh copies every shared file to its agents; the agent only reads it.
type SharedPaths struct {
	ACLPaths     []string `json:"acl_paths"`
	AuditWatches []string `json:"audit_watches"`
	// ExecWatches are binaries whose executions are audited (op.acc.3).
	ExecWatches []string `json:"exec_watches"`
}

// DefaultSharedPaths is where the Wazuh agent keeps that file.
const DefaultSharedPaths = "/var/ossec/etc/shared/oscompliance.json"

// readSharedPaths reads the file; absent is not an error (ok is false).
func readSharedPaths(path string) (paths SharedPaths, ok bool, err error) {

	data, err := fsread.ReadFile(path)

	if errors.Is(err, fs.ErrNotExist) {
		return SharedPaths{}, false, nil
	}
	if err != nil {
		return SharedPaths{}, false, err
	}

	if err := json.Unmarshal(data, &paths); err != nil {
		return SharedPaths{}, false, err
	}

	return paths, true, nil
}

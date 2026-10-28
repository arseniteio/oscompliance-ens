package wazuh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

type AgentConfigPaths struct {
	OssecConf  string
	SharedConf string
	ClientKeys string
}

var DefaultAgentConfig = AgentConfigPaths{
	OssecConf:  "/var/ossec/etc/ossec.conf",
	SharedConf: "/var/ossec/etc/shared/agent.conf",
	ClientKeys: "/var/ossec/etc/client.keys",
}

func CollectAgentConfig(e *emit.Emitter, cfg AgentConfigPaths) error {

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

type SharedPaths struct {
	ACLPaths     []string `json:"acl_paths"`
	AuditWatches []string `json:"audit_watches"`

	ExecWatches []string `json:"exec_watches"`
}

// The engine writes the paths as a comment inside the group configuration: the Wazuh API only writes
// agent.conf, and an unknown element would make the manager reject the file.
const ManagedPathsMarker = "oscompliance "

// ReadSharedPaths returns the paths of the last applicable block that carries them: a block naming
// this machine comes after the group-wide one and replaces it.
func ReadSharedPaths(cfg AgentConfigPaths) (paths SharedPaths, ok bool, err error) {

	data, err := fsread.ReadFile(cfg.SharedConf)

	if errors.Is(err, fs.ErrNotExist) {
		return SharedPaths{}, false, nil
	}
	if err != nil {
		return SharedPaths{}, false, err
	}

	blocks, err := applicableBlocks(data, "agent_config", agentName(cfg.ClientKeys))
	if err != nil {
		return SharedPaths{}, false, err
	}

	// encoding/xml joins every comment of a block into one string.
	for _, b := range blocks {
		_, body, found := strings.Cut(b.Comments, ManagedPathsMarker+"{")
		if !found {
			continue
		}
		var next SharedPaths
		if err := json.NewDecoder(strings.NewReader("{" + body)).Decode(&next); err != nil {
			return SharedPaths{}, false, fmt.Errorf("managed paths: %w", err)
		}
		paths, ok = next, true
	}

	return paths, ok, nil
}

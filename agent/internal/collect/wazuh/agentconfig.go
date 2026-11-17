package wazuh

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
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
		Directories: []fact.FIMDirectory{}, Localfiles: []fact.AgentLocalfile{}, SyscollectorScans: []string{},
		SyscheckScanOnStart: true, Integrations: []string{}, ActiveResponses: activeResponses(filepath.Join(filepath.Dir(cfg.OssecConf), "shared", "ar.conf")),
		SealedDays:   sealedDays(filepath.Join(filepath.Dir(filepath.Dir(cfg.OssecConf)), "logs", "alerts"), time.Now()),
		Lists:        lists(filepath.Join(filepath.Dir(cfg.OssecConf), "lists")),
		RulesetFiles: len(files(filepath.Join(filepath.Dir(filepath.Dir(cfg.OssecConf)), "ruleset", "rules"))),
		CustomRules:  files(filepath.Join(filepath.Dir(cfg.OssecConf), "rules"))}
	inventory := syscollector{disabled: true}
	assessment := scaSettings{disabled: true}

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
	inventory.add(blocks)
	assessment.add(blocks)

	if shared, err := fsread.ReadFile(cfg.SharedConf); err == nil {
		blocks, err := applicableBlocks(shared, "agent_config", name)
		if err != nil {
			out.Status, out.Error = fact.SourceUnreadable, cfg.SharedConf+": "+err.Error()
			return e.Emit(out)
		}
		add(&out, blocks, cfg.SharedConf)
		inventory.add(blocks)
		assessment.add(blocks)
	} else if !errors.Is(err, fs.ErrNotExist) {
		out.Status, out.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(out)
	}

	out.SyscollectorDisabled, out.SyscollectorInterval, out.SyscollectorScans = inventory.disabled, inventory.interval, inventory.on()
	out.SCADisabled, out.SCAInterval = assessment.disabled, assessment.interval
	return e.Emit(out)
}

var syscollectorScans = []string{"hardware", "os", "network", "packages", "ports", "processes"}

type syscollector struct {
	seen     bool
	disabled bool
	interval int
	off      map[string]bool
}

func (s *syscollector) add(blocks []agentConfig) {

	for _, b := range blocks {
		for _, w := range b.Wodles {

			if w.Name != "syscollector" {
				continue
			}
			if !s.seen {
				s.seen, s.disabled, s.interval, s.off = true, false, 3600, map[string]bool{}
			}

			if d := strings.TrimSpace(w.Disabled); d != "" {
				s.disabled = d == "yes"
			}
			if n, ok := seconds(w.Interval); ok {
				s.interval = n
			}

			for scan, value := range map[string]string{"hardware": w.Hardware, "os": w.OS, "network": w.Network, "packages": w.Packages, "ports": w.Ports, "processes": w.Processes} {
				if v := strings.TrimSpace(value); v != "" {
					s.off[scan] = v != "yes"
				}
			}
		}
	}
}

func sealedDays(dir string, now time.Time) []string {
	out := []string{}
	for d := now.AddDate(0, 0, -400); !d.After(now); d = d.AddDate(0, 0, 1) {
		name := filepath.Join(dir, d.Format("2006"), d.Format("Jan"), "ossec-alerts-"+d.Format("02")+".log.sum")
		if _, err := os.Stat(name); err == nil {
			out = append(out, d.Format("2006-01-02"))
		}
	}
	return out
}

func files(dir string) []string {
	out := []string{}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".xml") {
			out = append(out, e.Name())
		}
	}
	return out
}

func lists(dir string) []fact.CDBList {
	out := []fact.CDBList{}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(path, ".cdb") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		out = append(out, fact.CDBList{Name: rel, Modified: info.ModTime().UTC().Format(time.RFC3339)})
		return nil
	})
	return out
}

func activeResponses(path string) []string {
	out := []string{}
	data, err := fsread.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, " - ")
		if len(f) < 2 {
			continue
		}
		script := strings.TrimSpace(f[1])
		if strings.HasPrefix(script, "restart-") || slices.Contains(out, script) {
			continue
		}
		out = append(out, script)
	}
	return out
}

type scaSettings struct {
	seen     bool
	disabled bool
	interval int
}

func (s *scaSettings) add(blocks []agentConfig) {
	for _, b := range blocks {
		for _, c := range b.SCA {
			if !s.seen {
				s.seen, s.disabled, s.interval = true, false, 43200
			}
			if e := strings.TrimSpace(c.Enabled); e != "" {
				s.disabled = e != "yes"
			}
			if n, ok := seconds(c.Interval); ok {
				s.interval = n
			}
		}
	}
	if !s.seen {
		s.interval = 0
	}
}

func (s *syscollector) on() []string {

	scans := []string{}
	if !s.seen {
		return scans
	}
	for _, scan := range syscollectorScans {
		if !s.off[scan] {
			scans = append(scans, scan)
		}
	}
	return scans
}

func seconds(value string) (int, bool) {

	v := strings.TrimSpace(value)
	if v == "" {
		return 0, false
	}

	unit := 1
	switch v[len(v)-1] {
	case 's':
		v = v[:len(v)-1]
	case 'm':
		unit, v = 60, v[:len(v)-1]
	case 'h':
		unit, v = 3600, v[:len(v)-1]
	case 'd':
		unit, v = 86400, v[:len(v)-1]
	case 'w':
		unit, v = 604800, v[:len(v)-1]
	}

	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n * unit, true
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
			if v := strings.TrimSpace(s.ScanOnStart); v != "" {
				out.SyscheckScanOnStart = v == "yes"
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

		for _, r := range b.Rootcheck {
			if v := strings.TrimSpace(r.Disabled); v != "" {
				out.RootcheckDisabled = v == "yes"
			}
		}
		for _, i := range b.Integrations {
			if n := strings.TrimSpace(i.Name); n != "" && !slices.Contains(out.Integrations, n) {
				out.Integrations = append(out.Integrations, n)
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
	ReadWatches  []string `json:"read_watches"`

	ExecWatches []string `json:"exec_watches"`

	BackupSources []string `json:"backup_sources"`
	BackupKeys    []string `json:"backup_keys"`
	KeyStores     []string `json:"key_stores"`
}

const ManagedPathsMarker = "oscompliance "

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

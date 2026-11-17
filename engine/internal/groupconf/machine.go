package groupconf

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/params"
)

type Machine struct {
	Paths    Paths
	FIM      []string
	Services []Service
}

type Paths struct {
	ACL   []string `json:"acl_paths"`
	Audit []string `json:"audit_watches"`
	Read  []string `json:"read_watches"`
	Exec  []string `json:"exec_watches"`

	Backup     []string `json:"backup_sources,omitempty"`
	BackupKeys []string `json:"backup_keys,omitempty"`
	Keys       []string `json:"key_stores,omitempty"`
}

type Service struct {
	Name string
	Log  string
}

var serviceConfigurations = []struct{ control, param string }{{"mp.com.3", "P-06"}, {"mp.s.1", "P-09"}}

var securityPaths = []string{"/var/ossec/etc", "/etc/audit", "/var/log/audit"}

const agentConfiguration = "/var/ossec/etc"

var keyTools = []string{"/usr/bin/ssh-keygen", "/usr/bin/openssl"}

var fimDefaults = []string{"/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/boot"}

func ForAgent(policy params.Lister, agentID, agentName string) Machine {

	var m Machine

	for _, p := range cells(policy, agentID, "op.acc.2", "P-02", 0) {
		if !underAny(p, fimDefaults) {
			m.FIM = append(m.FIM, p)
		}
	}

	for _, c := range serviceConfigurations {
		for _, p := range cells(policy, agentID, c.control, c.param, 0) {
			if !underAny(p, fimDefaults) {
				m.FIM = append(m.FIM, p)
			}
		}
	}

	m.Paths.ACL = cells(policy, agentID, "op.acc.2", "P-08", 0)
	m.Paths.ACL = append(m.Paths.ACL, cells(policy, agentID, "op.exp.2", "P-08", 0)...)
	m.Paths.ACL = append(m.Paths.ACL, cells(policy, agentID, "op.exp.8", "P-14", 0)...)
	m.Paths.Read = append(m.Paths.Read, cells(policy, agentID, "op.acc.2", "P-06", 1)...)
	m.Paths.Read = append(m.Paths.Read, cells(policy, agentID, "op.acc.4", "P-07", 0)...)
	m.Paths.Read = append(m.Paths.Read, securityPaths...)
	m.Paths.Audit = append(m.Paths.Audit, cells(policy, agentID, "op.exp.3", "P-04", 0)...)
	m.Paths.Backup = BackupSources(policy, agentID)
	m.Paths.BackupKeys = cells(policy, agentID, "mp.info.6", "P-08", 0)
	m.Paths.Keys = cells(policy, agentID, "op.exp.10", "P-02", 0)
	m.Paths.Read = append(m.Paths.Read, m.Paths.Keys...)
	if len(m.Paths.Keys) > 0 {
		m.Paths.Exec = append(m.Paths.Exec, keyTools...)
	}

	for _, indicator := range indicators(policy, agentID) {
		if isBinary(indicator) {
			m.Paths.Exec = append(m.Paths.Exec, indicator)
		} else {
			m.Paths.Read = append(m.Paths.Read, indicator)
		}
	}

	if rows, err := policy.List(agentID, "op.acc.5", "P-02"); err == nil {
		for _, r := range rows {
			c := split(r, 3)
			if c[0] != "" && c[2] != "" && strings.EqualFold(c[1], agentName) {
				m.Services = append(m.Services, Service{Name: c[0], Log: c[2]})
			}
		}
	}

	m.FIM = append(m.FIM, agentConfiguration)
	m.FIM = sorted(m.FIM)
	m.Paths.ACL = sorted(m.Paths.ACL)
	m.Paths.Read = sorted(m.Paths.Read)
	m.Paths.Audit = slices.DeleteFunc(sorted(m.Paths.Audit), func(p string) bool { return slices.Contains(m.Paths.Read, p) })
	m.Paths.Exec = sorted(m.Paths.Exec)
	m.Paths.Backup = sorted(m.Paths.Backup)
	m.Paths.BackupKeys = sorted(m.Paths.BackupKeys)
	m.Paths.Keys = sorted(m.Paths.Keys)
	slices.SortFunc(m.Services, func(a, b Service) int { return strings.Compare(a.Name+a.Log, b.Name+b.Log) })

	return m
}

func indicators(policy params.Lister, agentID string) []string {

	rows, err := policy.List(agentID, "op.acc.3", "P-03")
	if err != nil {
		return nil
	}

	var out []string
	for _, r := range rows {
		for _, c := range split(r, 0)[1:] {
			if filepath.IsAbs(c) {
				out = append(out, filepath.Clean(c))
			}
		}
	}
	return out
}

func BackupSources(policy params.Lister, agentID string) []string {
	return append(Sources(policy, agentID, "op.exp.3", "P-07"), Sources(policy, agentID, "mp.info.6", "P-04")...)
}

func Sources(policy params.Lister, agentID, controlID, paramID string) []string {

	rows, err := policy.List(agentID, controlID, paramID)
	if err != nil {
		return nil
	}

	var out []string
	for _, r := range rows {
		if src := Source(split(r, 2)[1]); src != "" {
			out = append(out, src)
		}
	}
	return out
}

func Source(src string) string {
	if dir, ok := strings.CutPrefix(src, "git:"); ok && filepath.IsAbs(dir) {
		return "git:" + filepath.Clean(dir)
	}
	if filepath.IsAbs(src) {
		return filepath.Clean(src)
	}
	return ""
}

func isBinary(path string) bool {
	dir := filepath.Base(filepath.Dir(path))
	return dir == "bin" || dir == "sbin"
}

func cells(policy params.Lister, agentID, controlID, paramID string, column int) []string {

	rows, err := policy.List(agentID, controlID, paramID)
	if err != nil {
		return nil
	}

	var out []string
	for _, r := range rows {
		if c := split(r, column+1)[column]; filepath.IsAbs(c) {
			out = append(out, filepath.Clean(c))
		}
	}
	return out
}

func split(row string, atLeast int) []string {
	c := strings.Split(row, "|")
	for i := range c {
		c[i] = strings.TrimSpace(c[i])
	}
	for len(c) < atLeast {
		c = append(c, "")
	}
	return c
}

func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		if path == d || strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

func sorted(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

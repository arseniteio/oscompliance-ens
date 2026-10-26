package sysconf

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// ServiceLabel is the localfile label that names an external-user service.
// The same label travels with every event, so Wazuh rule 119003 knows the
// service without the application writing it.
const ServiceLabel = "oscompliance_service"

// ServiceLogConfig says where the Wazuh agent keeps its shared
// configuration and its own name.
type ServiceLogConfig struct {
	SharedConf string // /var/ossec/etc/shared/agent.conf
	ClientKeys string // /var/ossec/etc/client.keys
}

// earliestLines bounds the search for the first contract line of a copy.
const earliestLines = 2000

// CollectServiceLogs emits one service_log per labelled localfile of the
// agent's shared configuration, then the service_log_snapshot. The agent
// is told nothing: it reads what the manager already gave the Wazuh agent.
func CollectServiceLogs(e *emit.Emitter, cfg ServiceLogConfig) error {

	snapshot := fact.ServiceLogSnapshot{Envelope: e.Envelope(fact.ServiceLogSnapshotFact), Config: cfg.SharedConf, Status: fact.SourceRead}
	snapshot.AgentName = agentName(cfg.ClientKeys)

	data, err := fsread.ReadFile(cfg.SharedConf)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		snapshot.Status = fact.SourceAbsent
		return e.Emit(snapshot)
	case err != nil:
		snapshot.Status, snapshot.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	}

	services, err := labelledLocalfiles(data, snapshot.AgentName)
	if err != nil {
		snapshot.Status, snapshot.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	}

	for _, s := range services {

		record := readServiceLog(s.service, s.path)
		record.Envelope = e.Envelope(fact.ServiceLogFact)

		if err := e.Emit(record); err != nil {
			return err
		}
		snapshot.RecordsEmitted++
	}

	return e.Emit(snapshot)
}

// agentName is the name the agent enrolled with: the second field of
// client.keys ("001 lab-agent-01 any <key>").
func agentName(clientKeys string) string {

	data, err := fsread.ReadFile(clientKeys)
	if err != nil {
		return ""
	}

	fields := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(fields) < 2 {
		return ""
	}

	return fields[1]
}

// agentConfig is one <agent_config> block of the shared configuration, or
// one <ossec_config> block of ossec.conf: both hold the same sections.
type agentConfig struct {
	Name       string      `xml:"name,attr"`
	OS         string      `xml:"os,attr"`
	Profile    string      `xml:"profile,attr"`
	Localfiles []localfile `xml:"localfile"`
	Syscheck   []syscheck  `xml:"syscheck"`
}

type localfile struct {
	Location string `xml:"location"`
	Format   string `xml:"log_format"`
	Labels   []struct {
		Key   string `xml:"key,attr"`
		Value string `xml:",chardata"`
	} `xml:"label"`
}

type syscheck struct {
	Disabled    string `xml:"disabled"`
	Frequency   string `xml:"frequency"`
	Directories []struct {
		Realtime string `xml:"realtime,attr"`
		Whodata  string `xml:"whodata,attr"`
		Paths    string `xml:",chardata"`
	} `xml:"directories"`
	Ignore []string `xml:"ignore"`
}

type serviceFile struct {
	service, path string
}

// labelledLocalfiles reads the agent_config blocks that apply to this agent,
// as the Wazuh agent does: blocks without attributes, blocks naming the
// agent, and blocks for its operating system. Profile blocks are left out:
// the profiles are in the agent's own ossec.conf.
func labelledLocalfiles(data []byte, name string) ([]serviceFile, error) {

	blocks, err := applicableBlocks(data, "agent_config", name)
	if err != nil {
		return nil, err
	}

	var out []serviceFile
	seen := map[string]bool{}

	for _, b := range blocks {

		for _, l := range b.Localfiles {
			for _, label := range l.Labels {
				key := l.Location + "\x00" + label.Value
				if label.Key == ServiceLabel && strings.TrimSpace(label.Value) != "" && !seen[key] {
					seen[key] = true
					out = append(out, serviceFile{service: strings.TrimSpace(label.Value), path: strings.TrimSpace(l.Location)})
				}
			}
		}
	}

	return out, nil
}

// applicableBlocks parses the <element> blocks of a Wazuh configuration and
// keeps those that apply to the agent named name, as the Wazuh agent does.
func applicableBlocks(data []byte, element, name string) ([]agentConfig, error) {

	decoder := xml.NewDecoder(io.MultiReader(strings.NewReader("<root>"), strings.NewReader(string(data)), strings.NewReader("</root>")))
	decoder.Strict = false

	var root struct {
		Agent []agentConfig `xml:"agent_config"`
		Ossec []agentConfig `xml:"ossec_config"`
	}
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}

	all := root.Agent
	if element == "ossec_config" {
		all = root.Ossec
	}

	var out []agentConfig
	for _, b := range all {
		switch {
		case b.Profile != "":
		case b.Name != "" && !nameMatches(b.Name, name):
		case b.OS != "" && !strings.Contains(strings.ToLower(b.OS), "linux"):
		default:
			out = append(out, b)
		}
	}

	return out, nil
}

func nameMatches(attr, name string) bool {
	for _, n := range strings.Split(attr, ",") {
		if strings.TrimSpace(n) == name && name != "" {
			return true
		}
	}
	return false
}

// readServiceLog stats the log and its rotated copies and finds how far
// back the oldest one reaches.
func readServiceLog(service, path string) fact.ServiceLog {

	record := fact.ServiceLog{Service: service, Path: path, Status: fact.SourceRead, Rotated: []fact.LogFile{}}

	current, err := statLog(path)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		record.Status = fact.SourceAbsent
	case err != nil:
		record.Status, record.Error = fact.SourceUnreadable, err.Error()
		return record
	default:
		record.Inode, record.Size, record.Modified = current.Inode, current.Size, current.Modified
	}

	var copies []string
	for _, pattern := range []string{path + ".*", path + "-*"} {
		matches, _ := filepath.Glob(pattern)
		copies = append(copies, matches...)
	}

	for _, c := range copies {
		if f, err := statLog(c); err == nil {
			record.Rotated = append(record.Rotated, f)
		}
	}

	sort.Slice(record.Rotated, func(i, j int) bool { return record.Rotated[i].Modified < record.Rotated[j].Modified })

	// The oldest copy holds the oldest lines.
	candidates := []string{}
	for _, f := range record.Rotated {
		candidates = append(candidates, f.Path)
	}
	if record.Status == fact.SourceRead {
		candidates = append(candidates, path)
	}

	for _, c := range candidates {
		if ts, ok := firstEventTime(c); ok {
			record.EarliestEvent = ts.UTC().Format(time.RFC3339)
			break
		}
	}

	return record
}

func statLog(path string) (fact.LogFile, error) {

	info, err := os.Stat(path)
	if err != nil {
		return fact.LogFile{}, err
	}

	f := fact.LogFile{Path: path, Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339)}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		f.Inode = uint64(st.Ino)
	}

	return f, nil
}

// firstEventTime is the ts of the first contract line of a log copy,
// compressed or not.
func firstEventTime(path string) (time.Time, bool) {

	file, err := fsread.Open(path)
	if err != nil {
		return time.Time{}, false
	}
	defer file.Close()

	var r io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return time.Time{}, false
		}
		defer gz.Close()
		r = gz
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for n := 0; n < earliestLines && scanner.Scan(); n++ {

		var line struct {
			TS   string `json:"ts"`
			Tipo string `json:"tipo"`
		}

		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Tipo == "" {
			continue
		}

		if ts, err := time.Parse(time.RFC3339, line.TS); err == nil {
			return ts, true
		}
	}

	return time.Time{}, false
}

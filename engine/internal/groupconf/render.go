package groupconf

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"slices"
	"strings"
)

const (
	begin = "<!-- oscompliance begin: written by oscompliance-engine from the ENS configuration, do not edit -->"
	end   = "<!-- oscompliance end -->"

	FactsLog = "/var/log/oscompliance/facts.ndjson"
	AuditLog = "/var/log/audit/audit.log"

	WindowsFactsLog = `C:\ProgramData\oscompliance\facts.ndjson`
	DefenderChannel = "Microsoft-Windows-Windows Defender/Operational"

	pathsMarker = "oscompliance "
)

type Agent struct {
	Name    string
	Machine Machine
}

func Region(agents []Agent) string {

	var linuxAgents, windowsAgents []Agent
	for _, a := range agents {
		if a.Machine.Windows {
			windowsAgents = append(windowsAgents, a)
		} else {
			linuxAgents = append(linuxAgents, a)
		}
	}

	var b strings.Builder
	b.WriteString(begin + "\n")

	// A group without Windows agents keeps the block every Linux agent already has.
	commons := map[bool]Machine{}
	switch {
	case len(windowsAgents) == 0:
		commons[false] = writeCommon(&b, "", linuxAgents)
	case len(linuxAgents) == 0:
		commons[true] = writeCommon(&b, osWindows, windowsAgents)
	default:
		commons[false] = writeCommon(&b, osLinux, linuxAgents)
		commons[true] = writeCommon(&b, osWindows, windowsAgents)
	}

	named := slices.Clone(agents)
	slices.SortFunc(named, func(a, b Agent) int { return strings.Compare(a.Name, b.Name) })

	for _, a := range named {

		ownPaths := sharedKey(a.Machine) != sharedKey(commons[a.Machine.Windows])
		if !ownPaths && len(a.Machine.Services) == 0 {
			continue
		}

		b.WriteString(`<agent_config name="` + escape(a.Name) + "\">\n")
		if ownPaths {
			writePaths(&b, a.Machine.Paths)
			writeFIM(&b, a.Machine.FIM)
		}
		for _, s := range a.Machine.Services {
			writeLocalfile(&b, s.Log, "json", s.Name)
		}
		b.WriteString("</agent_config>\n")
	}

	b.WriteString(end + "\n")
	return b.String()
}

const (
	osLinux   = "Linux"
	osWindows = "Windows"
)

func writeCommon(b *strings.Builder, os string, agents []Agent) Machine {

	common := mostShared(agents)

	if os == "" {
		b.WriteString("<agent_config>\n")
	} else {
		b.WriteString(`<agent_config os="` + os + "\">\n")
	}
	writePaths(b, common.Paths)
	if os == osWindows {
		writeLocalfile(b, WindowsFactsLog, "json", "")
		writeLocalfile(b, DefenderChannel, "eventchannel", "")
	} else {
		writeLocalfile(b, FactsLog, "json", "")
		writeLocalfile(b, AuditLog, "audit", "")
	}
	writeFIM(b, common.FIM)
	b.WriteString("</agent_config>\n")

	return common
}

func Merge(current, region string) string {

	i := strings.Index(current, begin)
	j := strings.Index(current, end)

	if i >= 0 && j > i {
		rest := strings.TrimPrefix(current[j+len(end):], "\n")
		return current[:i] + region + rest
	}

	current = strings.TrimRight(current, "\n")
	if current == "" {
		return region
	}
	return current + "\n" + region
}

func Current(conf string) string {
	i := strings.Index(conf, begin)
	j := strings.Index(conf, end)
	if i < 0 || j < i {
		return ""
	}
	return conf[i:j+len(end)] + "\n"
}

func Same(a, b string) bool {
	return strings.Join(lines(a), "\n") == strings.Join(lines(b), "\n")
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func mostShared(agents []Agent) Machine {

	count := map[string]int{}
	byKey := map[string]Machine{}
	for _, a := range agents {
		k := sharedKey(a.Machine)
		count[k]++
		byKey[k] = Machine{Windows: a.Machine.Windows, Paths: a.Machine.Paths, FIM: a.Machine.FIM}
	}

	best := ""
	for k, n := range count {
		if n > count[best] || (n == count[best] && k < best) {
			best = k
		}
	}

	return byKey[best]
}

func sharedKey(m Machine) string {
	k, _ := json.Marshal(struct {
		Paths Paths
		FIM   []string
	}{nonNil(m.Paths), m.FIM})
	return string(k)
}

func nonNil(p Paths) Paths {
	for _, l := range []*[]string{&p.ACL, &p.Audit, &p.Read, &p.Exec} {
		if *l == nil {
			*l = []string{}
		}
	}
	return p
}

func writePaths(b *strings.Builder, p Paths) {
	data, _ := json.Marshal(nonNil(p))
	b.WriteString("  <!-- " + pathsMarker + strings.ReplaceAll(string(data), "--", `-\u002d`) + " -->\n")
}

func writeLocalfile(b *strings.Builder, location, format, service string) {
	b.WriteString("  <localfile>\n    <log_format>" + format + "</log_format>\n    <location>" + escape(location) + "</location>\n")
	if service != "" {
		b.WriteString(`    <label key="oscompliance_service">` + escape(service) + "</label>\n")
	}
	b.WriteString("  </localfile>\n")
}

func writeFIM(b *strings.Builder, dirs []string) {
	if len(dirs) == 0 {
		return
	}
	b.WriteString("  <syscheck>\n")
	for _, d := range dirs {
		b.WriteString(`    <directories check_all="yes" realtime="yes">` + escape(d) + "</directories>\n")
	}
	b.WriteString("  </syscheck>\n")
}

func escape(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// Package opacc5 judges op.acc.5 (authentication mechanism, external
// users) from the authentication log of each external-user service: lines in
// the op.acc.5 contract that Wazuh reads with a labelled localfile (rule
// 119003), and the agent's view of the log files.
package opacc5

import (
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
)

// Service is one external-user service of the machine.
type Service struct {
	Name string
	// Declared: the service is a row of P-02 for this machine.
	Declared bool
	// Log is the agent's newest view of the log file; nil when the agent
	// does not read it (no labelled localfile reached it).
	Log *fact.ServiceLog
	// Span is what the index keeps of the service's events.
	Span source.ServiceSpan
}

// Services joins P-02 with what the agent reads and what Wazuh indexed.
func Services(declared []string, logs []fact.ServiceLog, spans map[string]source.ServiceSpan) []Service {

	byName := map[string]*Service{}
	get := func(name string) *Service {
		s, ok := byName[name]
		if !ok {
			s = &Service{Name: name}
			byName[name] = s
		}
		return s
	}

	for _, d := range declared {
		get(d).Declared = true
	}
	for i := range logs {
		get(logs[i].Service).Log = &logs[i]
	}
	for name, span := range spans {
		get(name).Span = span
	}

	var out []Service
	for _, s := range byName {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

	return out
}

// declaredNames reads the servicio column of P-02 rows.
func declaredNames(rows []string) []string {

	var out []string
	for _, r := range rows {
		name, _, _ := strings.Cut(r, "|")
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name)
		}
	}
	return out
}

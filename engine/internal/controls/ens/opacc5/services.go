package opacc5

import (
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
)

type Service struct {
	Name string

	Declared bool

	Log *fact.ServiceLog

	Span source.ServiceSpan
}

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

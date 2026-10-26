package opacc6

import (
	"slices"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Settings struct {
	Snapshot *fact.ConfigSnapshot
	Files    []fact.ConfigFile
}

func (s Settings) Gap() (verdict.Judgement, bool) {
	return passes.ConfigGap(s.Snapshot, s.Files)
}

func (s Settings) sorted() []fact.ConfigFile {
	files := slices.Clone(s.Files)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Source < files[j].Source })
	return files
}

type Value struct {
	Value  string
	Source string
	Found  bool
}

func (s Settings) Lookup(main, section, key string) (v Value, unreadable []string, seen bool) {

	for _, f := range s.sorted() {

		if f.Source != main && !strings.HasPrefix(f.Source, main+".d/") {
			continue
		}

		seen = true

		if f.Status == fact.SourceUnreadable || f.Status == fact.SourceError {
			unreadable = append(unreadable, f.Source+": "+f.Error)
			continue
		}

		for _, e := range f.Entries {
			if strings.EqualFold(e.Key, key) && strings.EqualFold(e.Section, section) {
				v = Value{Value: e.Value, Source: f.Source, Found: true}
			}
		}
	}

	return v, unreadable, seen
}

func (s Settings) Command(suffix string) (fact.ConfigFile, bool) {

	for _, f := range s.Files {
		if f.Kind == fact.ConfigKindCommand && strings.HasSuffix(f.Source, suffix) {
			return f, true
		}
	}

	return fact.ConfigFile{}, false
}

type SSHD struct {
	Status string
	Error  string
	Values map[string][]string
}

func (s Settings) SSHD() SSHD {

	f, ok := s.Command(" -T")
	if !ok {
		return SSHD{}
	}

	out := SSHD{Status: f.Status, Error: f.Error, Values: map[string][]string{}}

	for _, e := range f.Entries {
		key := strings.ToLower(e.Key)
		out.Values[key] = append(out.Values[key], e.Value)
	}

	return out
}

func (d SSHD) Get(key string) string {
	if v := d.Values[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (s Settings) HasMatch() bool {

	for _, f := range s.Files {
		if f.Source != "/etc/ssh/sshd_config" && !strings.HasPrefix(f.Source, "/etc/ssh/sshd_config.d/") {
			continue
		}
		for _, e := range f.Entries {
			if strings.EqualFold(e.Key, "match") {
				return true
			}
		}
	}

	return false
}

type PAM struct {
	Snapshot *fact.PAMSnapshot
	Rules    []fact.PAMRule
}

func (p PAM) Gap() (verdict.Judgement, bool) {
	return passes.PAMGap(p.Snapshot, p.Rules)
}

func (p PAM) Has(service string) bool {
	return p.Snapshot != nil && slices.Contains(p.Snapshot.Services, service)
}

func (p PAM) Stack(service, kind string) []fact.PAMRule {

	var out []fact.PAMRule

	for _, r := range p.Rules {
		if r.Service == service && r.Type == kind && !r.ModuleMissing {
			out = append(out, r)
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out
}

func Arg(r fact.PAMRule, name string) (string, bool) {

	value, found := "", false

	for _, a := range r.Args {
		k, v, _ := strings.Cut(a, "=")
		if k == name {
			value, found = v, true
		}
	}

	return value, found
}

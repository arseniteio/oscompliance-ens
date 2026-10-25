// Package opacc6 judges op.acc.6 (authentication mechanism, organisation
// users) from the configuration facts, the identity facts and the
// authentication alerts Wazuh raises by itself.
package opacc6

import (
	"slices"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Settings is one configuration read of an agent: every config_file of the
// newest config_snapshot.
type Settings struct {
	Snapshot *fact.ConfigSnapshot
	Files    []fact.ConfigFile
}

// Gap says why the read cannot be used at all.
func (s Settings) Gap() (verdict.Judgement, bool) {
	return passes.ConfigGap(s.Snapshot, s.Files)
}

// sorted orders the sources by path: a main file comes before its drop-in
// directory ("pwquality.conf" < "pwquality.conf.d/a.conf") and drop-ins in
// name order, the order programs read them in, so the last value wins.
func (s Settings) sorted() []fact.ConfigFile {
	files := slices.Clone(s.Files)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Source < files[j].Source })
	return files
}

// Value is one effective setting and where it comes from.
type Value struct {
	Value  string
	Source string
	Found  bool
}

// Lookup returns the last value of key (case-insensitive) among the sources
// whose path is main or lies in main's drop-in directory (main + ".d/"),
// keeping only entries of the given section ("" for none). unreadable lists
// the sources that could not be read: the value may be wrong when it is not
// empty.
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

// Command returns the source of a command whose name ends in suffix
// (" -T" for sshd, " -V" for ssh).
func (s Settings) Command(suffix string) (fact.ConfigFile, bool) {

	for _, f := range s.Files {
		if f.Kind == fact.ConfigKindCommand && strings.HasSuffix(f.Source, suffix) {
			return f, true
		}
	}

	return fact.ConfigFile{}, false
}

// SSHD is the effective sshd configuration (sshd -T): lowercase keys, every
// value of a repeated key in order.
type SSHD struct {
	Status string // read, absent (sshd not installed), error; "" not reported
	Error  string
	Values map[string][]string
}

// SSHD reads sshd -T out of the configuration read.
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

// Get is the first value of key, "" when sshd -T does not print it.
func (d SSHD) Get(key string) string {
	if v := d.Values[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// HasMatch reports whether sshd_config or a drop-in declares a Match block:
// sshd -T shows the configuration outside them only.
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

// PAM is one PAM read of an agent.
type PAM struct {
	Snapshot *fact.PAMSnapshot
	Rules    []fact.PAMRule
}

// Gap says why the read cannot be used at all.
func (p PAM) Gap() (verdict.Judgement, bool) {
	return passes.PAMGap(p.Snapshot, p.Rules)
}

// Has reports whether the service has a PAM file.
func (p PAM) Has(service string) bool {
	return p.Snapshot != nil && slices.Contains(p.Snapshot.Services, service)
}

// Stack returns the resolved rules of one type of one service, in order.
func (p PAM) Stack(service, kind string) []fact.PAMRule {

	var out []fact.PAMRule

	for _, r := range p.Rules {
		if r.Service == service && r.Type == kind {
			out = append(out, r)
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out
}

// Arg returns the value of "name=value" in a rule's arguments, and whether
// it is there; a bare "name" is found with an empty value.
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

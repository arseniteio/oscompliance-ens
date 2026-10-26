package sysconf

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// PAMConfig says which PAM services are resolved and emitted.
type PAMConfig struct {
	Dir      string
	Services []string
	// Types keeps only rules of these types; empty keeps all four.
	Types []string
}

// DefaultPAMServices are the entry points of authentication on Linux: remote
// and console login, the graphical greeters, su, sudo and password change.
// common-* (Debian) and system-auth, password-auth (RHEL) are reached
// through their includes, as PAM reaches them.
var DefaultPAMServices = []string{"sshd", "login", "gdm-password", "lightdm", "sddm", "su", "su-l", "sudo", "passwd"}

// DefaultPAMTypes are the stacks the controls judge: how users authenticate
// (lockout, second factor, su restrictions) and how passwords are set
// (quality, history). account and session would double the facts unused.
var DefaultPAMTypes = []string{"auth", "password"}

// maxIncludeDepth stops include loops PAM itself would reject.
const maxIncludeDepth = 10

// maxProblems keeps the snapshot small; the count is what matters.
const maxProblems = 20

var pamTypes = map[string]bool{"auth": true, "account": true, "password": true, "session": true}

// CollectPAM emits the resolved stack of every service that exists, rule by
// rule, then the pam_snapshot.
func CollectPAM(e *emit.Emitter, cfg PAMConfig) error {

	snapshot := fact.PAMSnapshot{Envelope: e.Envelope(fact.PAMSnapshotFact), Services: []string{}, Status: fact.SourceRead}

	info, err := os.Stat(cfg.Dir)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		snapshot.Status = fact.SourceAbsent
		return e.Emit(snapshot)
	case err != nil:
		snapshot.Status, snapshot.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(snapshot)
	case !info.IsDir():
		snapshot.Status, snapshot.Error = fact.SourceUnreadable, cfg.Dir+" is not a directory"
		return e.Emit(snapshot)
	}

	for _, service := range cfg.Services {

		path := filepath.Join(cfg.Dir, service)

		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		}

		s := &stack{dir: cfg.Dir, service: service, types: cfg.Types}
		s.read(path, "", nil)

		snapshot.Services = append(snapshot.Services, service)

		for _, problem := range s.problems {
			if len(snapshot.Problems) < maxProblems {
				snapshot.Problems = append(snapshot.Problems, problem)
			}
		}

		for _, rule := range s.rules {

			rule.Envelope = e.Envelope(fact.PAMRuleFact)

			if err := e.Emit(rule); err != nil {
				return err
			}
			snapshot.RecordsEmitted++
		}
	}

	return e.Emit(snapshot)
}

// stack accumulates the resolved rules of one service.
type stack struct {
	dir      string
	service  string
	types    []string
	rules    []fact.PAMRule
	problems []string
}

// read appends the rules of one file. only limits them to one type, for
// "type include file" and "type substack file"; via is the include chain.
func (s *stack) read(path, only string, via []string) {

	if len(via) >= maxIncludeDepth || slices.Contains(via, path) {
		s.problems = append(s.problems, fmt.Sprintf("%s: include loop through %s", s.service, path))
		return
	}

	lines, err := pamLines(path)

	if err != nil {
		s.problems = append(s.problems, fmt.Sprintf("%s: %v", s.service, err))
		return
	}

	inner := append(append([]string(nil), via...), path)

	for _, l := range lines {

		fields := pamFields(l.text)

		if len(fields) == 2 && fields[0] == "@include" {
			s.read(s.target(fields[1]), only, inner)
			continue
		}

		if len(fields) < 3 {
			s.problems = append(s.problems, fmt.Sprintf("%s:%d: not a PAM rule", path, l.n))
			continue
		}

		kind := strings.TrimPrefix(fields[0], "-")

		if !pamTypes[kind] {
			s.problems = append(s.problems, fmt.Sprintf("%s:%d: unknown type %q", path, l.n, fields[0]))
			continue
		}

		if only != "" && kind != only {
			continue
		}

		if fields[1] == "include" || fields[1] == "substack" {
			s.read(s.target(fields[2]), kind, inner)
			continue
		}

		if len(s.types) > 0 && !slices.Contains(s.types, kind) {
			continue
		}

		s.rules = append(s.rules, fact.PAMRule{
			Service:  s.service,
			Position: len(s.rules),
			Type:     kind,
			Control:  fields[1],
			Module:   filepath.Base(fields[2]),
			Args:     append([]string{}, fields[3:]...),
			File:     path,
			Line:     l.n,
			Via:      via,
		})
	}
}

// target is the file an include names: relative to the PAM directory.
func (s *stack) target(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(s.dir, name)
}

type pamLine struct {
	n    int
	text string
}

// pamLines returns the rules of a file with comments dropped and backslash
// continuations joined; n is the line the rule starts on.
func pamLines(path string) ([]pamLine, error) {

	file, err := fsread.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []pamLine
	var pending strings.Builder
	start, n := 0, 0

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		n++
		text := scanner.Text()

		if pending.Len() == 0 {
			start = n
		}

		if strings.HasSuffix(text, "\\") {
			pending.WriteString(strings.TrimSuffix(text, "\\") + " ")
			continue
		}

		pending.WriteString(text)
		line := strings.TrimSpace(stripPAMComment(pending.String()))
		pending.Reset()

		if line != "" {
			lines = append(lines, pamLine{n: start, text: line})
		}
	}

	return lines, scanner.Err()
}

// stripPAMComment drops a "#" comment outside [...] brackets.
func stripPAMComment(line string) string {

	depth := 0

	for i, r := range line {
		switch {
		case r == '[':
			depth++
		case r == ']' && depth > 0:
			depth--
		case r == '#' && depth == 0:
			return line[:i]
		}
	}

	return line
}

// pamFields splits a rule on blanks, keeping a [...] group as one field:
// "[success=1 default=ignore]" is one control, "[a b]" one argument.
func pamFields(line string) []string {

	var fields []string
	var current strings.Builder
	depth := 0

	for _, r := range line {
		switch {
		case r == '[':
			depth++
			current.WriteRune(r)
		case r == ']' && depth > 0:
			depth--
			current.WriteRune(r)
		case (r == ' ' || r == '\t') && depth == 0:
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		fields = append(fields, current.String())
	}

	return fields
}

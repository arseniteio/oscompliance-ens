package pam

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	Dir      string
	Services []string

	Types []string
}

var DefaultServices = []string{"sshd", "login", "gdm-password", "lightdm", "sddm", "su", "su-l", "sudo", "passwd"}

var DefaultTypes = []string{"auth", "password"}

const maxIncludeDepth = 10

const maxProblems = 20

var pamTypes = map[string]bool{"auth": true, "account": true, "password": true, "session": true}

func Collect(e *emit.Emitter, cfg Config) error {

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

type stack struct {
	dir      string
	service  string
	types    []string
	rules    []fact.PAMRule
	problems []string
}

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
			ModuleMissing: !moduleInstalled(fields[2]),
			Service:       s.service,
			Position:      len(s.rules),
			Type:          kind,
			Control:       fields[1],
			Module:        filepath.Base(fields[2]),
			Args:          judgedArgs(fields[3:]),
			File:          path,
			Line:          l.n,
			Via:           via,
		})
	}
}

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

var moduleDirs = []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security", "/lib/*/security", "/usr/lib/*/security"}

var installed = map[string]bool{}

func moduleInstalled(module string) bool {

	if found, seen := installed[module]; seen {
		return found
	}

	found := false
	if filepath.IsAbs(module) {
		_, err := os.Stat(module)
		found = err == nil
	} else {
		for _, d := range moduleDirs {
			if matches, _ := filepath.Glob(filepath.Join(d, module)); len(matches) > 0 {
				found = true
				break
			}
		}
	}

	installed[module] = found
	return found
}

var pamArgs = map[string]bool{
	"deny": true, "unlock_time": true, "minlen": true, "minclass": true, "dcredit": true, "ucredit": true,
	"lcredit": true, "ocredit": true, "dictcheck": true, "remember": true, "obscure": true, "trust": true,
}

func judgedArgs(args []string) []string {
	out := []string{}
	for _, a := range args {
		name, _, _ := strings.Cut(a, "=")
		if pamArgs[name] {
			out = append(out, a)
		}
	}
	return out
}

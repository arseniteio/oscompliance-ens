package sudoers

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// Config: the main sudoers file; includes are followed from it.
type Config struct {
	Path string
}

// maxIncludeDepth and maxAliasDepth bound include and User_Alias recursion.
const (
	maxIncludeDepth = 8
	maxAliasDepth   = 5
	maxBlindReasons = 20
)

var aliasName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Collect emits one sudo_grant per subject of every user
// specification, then the sudoers_snapshot. Groups and UIDs are not resolved:
// the engine does it against the identity and group facts.
func Collect(e *emit.Emitter, cfg Config) error {

	p := sudoParser{aliases: map[string][]string{}, commands: map[string][]string{}, seen: map[string]bool{}}

	snapshot := fact.SudoersSnapshot{Envelope: e.Envelope(fact.SudoersSnapshotFact), Files: []fact.SudoersFile{}}

	switch status := p.readFile(cfg.Path, 0); status {
	case fact.SourceAbsent:
		// No sudo policy: nobody has sudo on this host.
		snapshot.Status = fact.SourceAbsent
	case fact.SourceUnreadable:
		snapshot.Status = fact.SourceUnreadable
	default:
		snapshot.Status = fact.SourceRead
	}

	snapshot.Files = p.files
	snapshot.Defaults = p.defaults

	// Aliases may be defined after their use: subjects are expanded once
	// every file is read.
	for _, spec := range p.specs {
		for _, g := range p.expand(spec) {
			g.Envelope = e.Envelope(fact.SudoGrantFact)
			if err := e.Emit(g); err != nil {
				return err
			}
			snapshot.RecordsEmitted++
		}
	}

	snapshot.BlindSpots = len(p.blind)
	if len(p.blind) > maxBlindReasons {
		snapshot.BlindSpotReasons = p.blind[:maxBlindReasons]
	} else {
		snapshot.BlindSpotReasons = p.blind
	}

	return e.Emit(snapshot)
}

type userSpec struct {
	users    []string
	file     string
	line     int
	nopasswd bool
	// commands is the right-hand side, expanded once every alias is known.
	commands string
	// spec is what is granted as written: hosts = runas commands.
	spec string
}

type sudoParser struct {
	aliases  map[string][]string
	commands map[string][]string
	defaults []fact.SudoDefault
	specs    []userSpec
	files    []fact.SudoersFile
	blind    []string
	seen     map[string]bool
}

func (p *sudoParser) blindSpot(file string, line int, why string) {
	p.blind = append(p.blind, fmt.Sprintf("%s:%d: %s", file, line, why))
}

// readFile reads one sudoers file and the files it includes. The returned
// status is the file's own.
func (p *sudoParser) readFile(path string, depth int) string {

	if p.seen[path] {
		return fact.SourceRead
	}
	p.seen[path] = true

	file, err := fsread.Open(path)

	if errors.Is(err, fs.ErrNotExist) {
		p.files = append(p.files, fact.SudoersFile{Path: path, Status: fact.SourceAbsent})
		return fact.SourceAbsent
	}

	if err != nil {
		p.files = append(p.files, fact.SudoersFile{Path: path, Status: fact.SourceUnreadable, Error: err.Error()})
		p.blindSpot(path, 0, "unreadable: "+err.Error())
		return fact.SourceUnreadable
	}

	defer file.Close()

	p.files = append(p.files, fact.SudoersFile{Path: path, Status: fact.SourceRead})

	scanner := bufio.NewScanner(file)
	lineNo, start := 0, 0
	var pending string

	for scanner.Scan() {

		lineNo++
		text := strings.TrimRight(scanner.Text(), "\r")

		if pending == "" {
			start = lineNo
		}

		// A trailing backslash continues the statement on the next line.
		if strings.HasSuffix(text, `\`) {
			pending += strings.TrimSuffix(text, `\`) + " "
			continue
		}

		stmt := pending + text
		pending = ""

		p.statement(path, start, stmt, depth)
	}

	if err := scanner.Err(); err != nil {
		p.blindSpot(path, lineNo, "read error: "+err.Error())
	}

	return fact.SourceRead
}

// statement handles one logical line.
func (p *sudoParser) statement(path string, line int, stmt string, depth int) {

	trimmed := strings.TrimSpace(stmt)

	// Includes: both the @ and the historical # forms.
	for _, kw := range []string{"@includedir", "#includedir", "@include", "#include"} {
		if strings.HasPrefix(trimmed, kw+" ") || strings.HasPrefix(trimmed, kw+"\t") {
			target := strings.TrimSpace(strings.TrimPrefix(trimmed, kw))
			p.include(path, line, kw, target, depth)
			return
		}
	}

	// "#" starts a comment unless it is a #uid in a user list.
	stmt = stripComment(stmt)
	trimmed = strings.TrimSpace(stmt)

	if trimmed == "" {
		return
	}

	first := strings.Fields(trimmed)[0]

	switch {
	case strings.HasPrefix(first, "Defaults"):
		p.defaultsLine(path, line, first, strings.TrimSpace(strings.TrimPrefix(trimmed, first)))
		return
	case first == "Cmnd_Alias" || first == "Cmd_Alias":
		p.cmndAlias(strings.TrimSpace(strings.TrimPrefix(trimmed, first)))
		return
	case first == "Host_Alias" || first == "Runas_Alias":
		return
	case first == "User_Alias":
		p.userAlias(path, line, strings.TrimSpace(strings.TrimPrefix(trimmed, "User_Alias")))
		return
	}

	p.userSpecification(path, line, trimmed)
}

func (p *sudoParser) include(path string, line int, kw, target string, depth int) {

	if depth >= maxIncludeDepth {
		p.blindSpot(path, line, "includes nested too deep")
		return
	}

	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}

	if !strings.HasSuffix(kw, "dir") {
		p.readFile(target, depth+1)
		return
	}

	entries, err := os.ReadDir(target)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		p.blindSpot(target, 0, "unreadable directory: "+err.Error())
		return
	}

	names := []string{}
	for _, e := range entries {
		// sudo skips names ending in ~ or containing a dot.
		if e.IsDir() || strings.HasSuffix(e.Name(), "~") || strings.Contains(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	for _, n := range names {
		p.readFile(filepath.Join(target, n), depth+1)
	}
}

// stripComment removes a "#" comment, keeping #uid tokens.
func stripComment(s string) string {

	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			continue
		}
		return s[:i]
	}

	return s
}

// defaultsLine records every setting of "Defaults[binding] a, b=c, !d".
func (p *sudoParser) defaultsLine(path string, line int, keyword, settings string) {

	binding := strings.TrimPrefix(keyword, "Defaults")

	for _, setting := range splitCommas(settings) {
		p.defaults = append(p.defaults, fact.SudoDefault{Binding: binding, Setting: setting, File: path, Line: line})
	}
}

// cmndAlias: NAME = /bin/a, /bin/b [: NAME2 = c].
func (p *sudoParser) cmndAlias(rest string) {

	for _, def := range strings.Split(rest, ":") {
		name, members, ok := strings.Cut(def, "=")
		if name = strings.TrimSpace(name); ok && aliasName.MatchString(name) {
			p.commands[name] = splitCommas(members)
		}
	}
}

// userAlias: NAME = a, b [: NAME2 = c].
func (p *sudoParser) userAlias(path string, line int, rest string) {

	for _, def := range strings.Split(rest, ":") {
		name, members, ok := strings.Cut(def, "=")
		name = strings.TrimSpace(name)
		if !ok || !aliasName.MatchString(name) {
			p.blindSpot(path, line, "malformed User_Alias")
			continue
		}
		p.aliases[name] = splitList(members)
	}
}

// userSpecification: "user_list host_list = ..." Only the user list matters:
// every subject named there is granted something.
func (p *sudoParser) userSpecification(path string, line int, stmt string) {

	lhs, rhs, ok := strings.Cut(stmt, "=")
	if !ok {
		p.blindSpot(path, line, "not a user specification")
		return
	}

	// Commas may be followed by spaces inside the user list.
	compact := regexp.MustCompile(`\s*,\s*`).ReplaceAllString(strings.TrimSpace(lhs), ",")
	fields := strings.Fields(compact)

	if len(fields) < 2 {
		p.blindSpot(path, line, "user specification without host list")
		return
	}

	p.specs = append(p.specs, userSpec{
		users:    strings.Split(fields[0], ","),
		file:     path,
		line:     line,
		nopasswd: strings.Contains(rhs, "NOPASSWD:"),
		commands: rhs,
		spec:     strings.Join(fields[1:], " ") + "=" + strings.Join(strings.Fields(rhs), " "),
	})
}

// expand turns the user list of a specification into grants.
func (p *sudoParser) expand(spec userSpec) []fact.SudoGrant {

	var out []fact.SudoGrant
	p.expandInto(spec, spec.users, 0, &out)

	commands := p.noPasswdCommands(spec.commands)
	for i := range out {
		out[i].NoPasswdCommands = commands
		out[i].Spec = spec.spec
	}

	return out
}

// sudoTags are the tags that may precede a command; NOPASSWD and PASSWD
// carry over to the commands after them until the other one appears.
var sudoTags = regexp.MustCompile(`^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:\s*`)

// sudoOptions are the Option_Spec words before a command (CWD=/tmp).
var sudoOptions = regexp.MustCompile(`^(ROLE|TYPE|CHROOT|CWD|NOTBEFORE|NOTAFTER|TIMEOUT|APPARMOR_PROFILE|PRIVS|LIMITPRIVS)=\S+\s*`)

// runasSpec is the "(user : group)" in front of a command.
var runasSpec = regexp.MustCompile(`^\([^)]*\)\s*`)

// noPasswdCommands lists the commands of a right-hand side that run without
// a password.
func (p *sudoParser) noPasswdCommands(rhs string) []string {

	var out []string
	nopasswd := false

	for _, item := range splitCommas(rhs) {

		cmd := stripCommandPrefix(item, &nopasswd)

		if !nopasswd || cmd == "" || strings.HasPrefix(cmd, "!") {
			continue
		}

		out = append(out, p.expandCommand(cmd, 0)...)
	}

	return out
}

// stripCommandPrefix drops the runas, options and tags in front of a
// command, updating nopasswd when a NOPASSWD or PASSWD tag is among them.
func stripCommandPrefix(item string, nopasswd *bool) string {

	for {
		item = strings.TrimSpace(item)

		switch {
		case runasSpec.MatchString(item):
			item = runasSpec.ReplaceAllString(item, "")
		case sudoOptions.MatchString(item):
			item = sudoOptions.ReplaceAllString(item, "")
		case sudoTags.MatchString(item):
			tag := sudoTags.FindStringSubmatch(item)[1]
			if tag == "NOPASSWD" || tag == "PASSWD" {
				*nopasswd = tag == "NOPASSWD"
			}
			item = sudoTags.ReplaceAllString(item, "")
		default:
			return item
		}
	}
}

// expandCommand replaces a Cmnd_Alias by its commands; an unknown alias
// stays as its name, which the engine reads as not resolved.
func (p *sudoParser) expandCommand(cmd string, depth int) []string {

	members, ok := p.commands[cmd]

	if cmd == "ALL" || !aliasName.MatchString(cmd) || !ok || depth >= maxAliasDepth {
		return []string{cmd}
	}

	var out []string
	for _, m := range members {
		if !strings.HasPrefix(m, "!") {
			out = append(out, p.expandCommand(m, depth+1)...)
		}
	}
	return out
}

// splitCommas splits a sudoers list on commas outside parentheses and
// quotes; "\," is an escaped comma inside a command.
func splitCommas(s string) []string {

	var out []string
	var current strings.Builder
	depth, quoted := 0, false

	flush := func() {
		if item := strings.TrimSpace(current.String()); item != "" {
			out = append(out, item)
		}
		current.Reset()
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			current.WriteByte(c)
			current.WriteByte(s[i+1])
			i++
		case c == '"':
			quoted = !quoted
			current.WriteByte(c)
		case c == '(' && !quoted:
			depth++
			current.WriteByte(c)
		case c == ')' && !quoted && depth > 0:
			depth--
			current.WriteByte(c)
		case c == ',' && !quoted && depth == 0:
			flush()
		default:
			current.WriteByte(c)
		}
	}
	flush()

	return out
}

func (p *sudoParser) expandInto(spec userSpec, users []string, depth int, out *[]fact.SudoGrant) {

	for _, raw := range users {

		u := strings.TrimSpace(raw)
		if u == "" {
			continue
		}

		// A negated subject grants nothing.
		if strings.HasPrefix(u, "!") {
			continue
		}

		grant := fact.SudoGrant{File: spec.file, Line: spec.line, NoPasswd: spec.nopasswd}

		switch {
		case u == "ALL":
			p.blindSpot(spec.file, spec.line, "ALL users granted")
			continue
		case strings.HasPrefix(u, "%:"), strings.HasPrefix(u, "+"), strings.HasPrefix(u, "%+"):
			p.blindSpot(spec.file, spec.line, "non-Unix group or netgroup "+u)
			continue
		case strings.HasPrefix(u, "%#"):
			grant.SubjectKind, grant.Subject = "gid", strings.TrimPrefix(u, "%#")
		case strings.HasPrefix(u, "%"):
			grant.SubjectKind, grant.Subject = "group", strings.TrimPrefix(u, "%")
		case strings.HasPrefix(u, "#"):
			grant.SubjectKind, grant.Subject = "uid", strings.TrimPrefix(u, "#")
		case aliasName.MatchString(u):
			members, ok := p.aliases[u]
			if !ok || depth >= maxAliasDepth {
				p.blindSpot(spec.file, spec.line, "unknown or too deep User_Alias "+u)
				continue
			}
			p.expandInto(spec, members, depth+1, out)
			continue
		default:
			grant.SubjectKind, grant.Subject = "user", strings.Trim(u, `"`)
		}

		*out = append(*out, grant)
	}
}

func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

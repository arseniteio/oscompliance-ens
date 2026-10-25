package opacc6

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Sudoers is one sudoers read of an agent.
type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

// EV09Input is what EV-09 (re-authentication at critical points) needs.
type EV09Input struct {
	Sudoers Sudoers
	PAM     PAM

	// Points is P-08: "sudo", "su", "sudo:/path"; PointsProblem says why
	// it cannot be used.
	Points        []string
	PointsProblem string
}

// Finding is one critical point reached without authenticating again.
type Finding struct {
	Point  string // sudo, su, sudo:/path
	Detail string
}

var undefinedAlias = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// JudgeEV09 judges EV-09 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. P-08 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Findings: sudo without a password for every command (NOPASSWD: ALL),
//     with authentication switched off (!authenticate) or a credential
//     cached forever (timestamp_timeout below 0) is point "sudo"; NOPASSWD
//     on one command is "sudo:<command>"; su trusting the wheel group is
//     "su". root's own grants are left out: root needs no elevation.
//  3. A finding at a point listed in P-08: NON_COMPLIANT. As P-08 says, a
//     NOPASSWD on one command only counts when that command is listed; a
//     "sudo" finding covers every command, so any listed sudo point fails.
//  4. A listed point that could not be read (sudoers or PAM unusable, an
//     undefined command alias): NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT.
func JudgeEV09(in EV09Input) verdict.Judgement {

	// 1. Parameter.
	if in.PointsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-08: "+in.PointsProblem)
	}

	listed := map[string]bool{}
	for _, p := range in.Points {
		listed[strings.ToLower(strings.TrimSpace(p))] = true
	}

	sudoListed := false
	for p := range listed {
		if p == "sudo" || strings.HasPrefix(p, "sudo:") {
			sudoListed = true
		}
	}

	var findings []Finding
	var unknown []string

	// 2. sudo.
	switch {
	case !sudoListed:
	case in.Sudoers.Snapshot == nil:
		unknown = append(unknown, "no sudoers_snapshot in the window")
	case in.Sudoers.Snapshot.Status == fact.SourceAbsent:
		// No sudo on this host: nothing to re-authenticate.
	case in.Sudoers.Snapshot.Status != fact.SourceRead:
		unknown = append(unknown, "sudoers unreadable")
	case len(in.Sudoers.Grants) < in.Sudoers.Snapshot.RecordsEmitted:
		unknown = append(unknown, fmt.Sprintf("sudoers read incomplete: %d of %d sudo_grant received", len(in.Sudoers.Grants), in.Sudoers.Snapshot.RecordsEmitted))
	default:
		f, u := sudoFindings(in.Sudoers)
		findings, unknown = append(findings, f...), append(unknown, u...)
	}

	// su.
	if listed["su"] {
		f, u := suFindings(in.PAM)
		findings, unknown = append(findings, f...), append(unknown, u...)
	}

	// 3. Findings at listed points. Point "sudo" covers every command, so it
	// reaches any listed sudo point.
	var failing []string
	for _, f := range findings {
		if listed[strings.ToLower(f.Point)] || (f.Point == "sudo" && sudoListed) {
			failing = append(failing, f.Point+" ("+f.Detail+")")
		}
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "no re-authentication at: " + strings.Join(failing, "; ")}
	}

	// 4. What could not be read.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unknown, "; "))
	}

	// 5. Every listed point asks for the credential again.
	return verdict.Judgement{Status: verdict.Compliant, Reason: "re-authentication required at " + strings.Join(in.Points, ", ")}
}

// sudoFindings reads grants and Defaults; unknown lists aliases that hide
// which commands run without a password.
func sudoFindings(s Sudoers) (findings []Finding, unknown []string) {

	for _, g := range s.Grants {

		if (g.SubjectKind == "user" && g.Subject == "root") || (g.SubjectKind == "uid" && g.Subject == "0") {
			continue
		}

		where := fmt.Sprintf("%s %s, %s:%d", g.SubjectKind, g.Subject, g.File, g.Line)

		for _, cmd := range g.NoPasswdCommands {
			switch {
			case cmd == "ALL":
				findings = append(findings, Finding{Point: "sudo", Detail: "NOPASSWD: ALL for " + where})
			case undefinedAlias.MatchString(cmd):
				unknown = append(unknown, "undefined Cmnd_Alias "+cmd+" for "+where)
			default:
				findings = append(findings, Finding{Point: "sudo:" + commandPath(cmd), Detail: "NOPASSWD for " + where})
			}
		}
	}

	for _, d := range s.Snapshot.Defaults {

		point := "sudo"
		if strings.HasPrefix(d.Binding, "!") {
			point = "sudo:" + commandPath(strings.TrimPrefix(d.Binding, "!"))
		}
		where := fmt.Sprintf("Defaults%s, %s:%d", d.Binding, d.File, d.Line)

		setting := strings.ReplaceAll(d.Setting, " ", "")

		switch {
		case setting == "!authenticate":
			findings = append(findings, Finding{Point: point, Detail: "!authenticate in " + where})
		case strings.HasPrefix(setting, "timestamp_timeout="):
			if n, err := strconv.ParseFloat(strings.TrimPrefix(setting, "timestamp_timeout="), 64); err == nil && n < 0 {
				findings = append(findings, Finding{Point: point, Detail: "credential cached without expiry in " + where})
			}
		}
	}

	return findings, unknown
}

// commandPath is the command without its arguments.
func commandPath(cmd string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	return path
}

// suFindings: pam_wheel with "trust" lets the wheel group su without a
// password.
func suFindings(pam PAM) (findings []Finding, unknown []string) {

	if gap, found := pam.Gap(); found {
		return nil, []string{"su: " + gap.Reason}
	}

	for _, service := range []string{"su", "su-l"} {
		for _, r := range pam.Stack(service, "auth") {
			if _, trust := Arg(r, "trust"); r.Module == "pam_wheel.so" && trust {
				findings = append(findings, Finding{Point: "su", Detail: fmt.Sprintf("pam_wheel trust in %s:%d", r.File, r.Line)})
			}
		}
	}

	return findings, nil
}

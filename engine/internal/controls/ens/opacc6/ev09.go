package opacc6

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

type EV09Input struct {
	Sudoers Sudoers
	PAM     PAM

	Points        []string
	PointsProblem string
}

type Finding struct {
	Point  string
	Detail string
}

var undefinedAlias = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func JudgeEV09(in EV09Input) verdict.Judgement {

	if in.PointsProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_08_a", "a", in.PointsProblem))
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

	switch {
	case !sudoListed:
	case in.Sudoers.Snapshot == nil:
		unknown = append(unknown, "no sudoers_snapshot in the window")
	case in.Sudoers.Snapshot.Status == fact.SourceAbsent:

	case in.Sudoers.Snapshot.Status != fact.SourceRead:
		unknown = append(unknown, "sudoers unreadable")
	case len(in.Sudoers.Grants) < in.Sudoers.Snapshot.RecordsEmitted:
		unknown = append(unknown, fmt.Sprintf("sudoers read incomplete: %d of %d sudo_grant received", len(in.Sudoers.Grants), in.Sudoers.Snapshot.RecordsEmitted))
	default:
		f, u := sudoFindings(in.Sudoers)
		findings, unknown = append(findings, f...), append(unknown, u...)

		if b := in.Sudoers.Snapshot.BlindSpots; b > 0 {
			unknown = append(unknown, fmt.Sprintf("sudoers has %d grants to unnamed subjects: %s", b, strings.Join(in.Sudoers.Snapshot.BlindSpotReasons, "; ")))
		}
	}

	if listed["su"] {
		f, u := suFindings(in.PAM)
		findings, unknown = append(findings, f...), append(unknown, u...)
	}

	var failing []string
	for _, f := range findings {
		if listed[strings.ToLower(f.Point)] || (f.Point == "sudo" && sudoListed) {
			failing = append(failing, f.Point+" ("+f.Detail+")")
		}
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.no_re_authentication_at_a", "a", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.a", "a", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.re_authentication_required_at_a", "a", in.Points))
}

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

func commandPath(cmd string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	return path
}

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

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
	PointsProblem catalog.Message
}

type Finding struct {
	Point  string
	Detail catalog.Message
}

var undefinedAlias = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func JudgeEV09(in EV09Input) verdict.Judgement {

	if !in.PointsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.PointsProblem)
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
	var unknown []catalog.Message

	switch {
	case !sudoListed:
	case in.Sudoers.Snapshot == nil:
		unknown = append(unknown, catalog.Says("gap.no_fact", "fact", "sudoers_snapshot"))
	case in.Sudoers.Snapshot.Status == fact.SourceAbsent:

	case in.Sudoers.Snapshot.Status != fact.SourceRead:
		unknown = append(unknown, catalog.Says("opacc6.unreadable", "file", "sudoers"))
	case len(in.Sudoers.Grants) < in.Sudoers.Snapshot.RecordsEmitted:
		unknown = append(unknown, catalog.Says("opacc6.sudoers_incomplete", "got", len(in.Sudoers.Grants), "want", in.Sudoers.Snapshot.RecordsEmitted))
	default:
		f, u := sudoFindings(in.Sudoers)
		findings, unknown = append(findings, f...), append(unknown, u...)

		if b := in.Sudoers.Snapshot.BlindSpots; b > 0 {
			unknown = append(unknown, catalog.Says("opacc6.sudoers_blind", "count", b, "reasons", strings.Join(in.Sudoers.Snapshot.BlindSpotReasons, "; ")))
		}
	}

	if listed["su"] {
		f, u := suFindings(in.PAM)
		findings, unknown = append(findings, f...), append(unknown, u...)
	}

	var failing []catalog.Message
	for _, f := range findings {
		if listed[strings.ToLower(f.Point)] || (f.Point == "sudo" && sudoListed) {
			failing = append(failing, catalog.Says("opacc6.point_detail", "point", f.Point, "detail", f.Detail))
		}
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.no_re_authentication_at_a", "a", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.re_authentication_required_at_a", "a", in.Points))
}

func sudoFindings(s Sudoers) (findings []Finding, unknown []catalog.Message) {

	for _, g := range s.Grants {

		if (g.SubjectKind == "user" && g.Subject == "root") || (g.SubjectKind == "uid" && g.Subject == "0") {
			continue
		}

		where := fmt.Sprintf("%s %s, %s:%d", g.SubjectKind, g.Subject, g.File, g.Line)

		for _, cmd := range g.NoPasswdCommands {
			switch {
			case cmd == "ALL":
				findings = append(findings, Finding{Point: "sudo", Detail: catalog.Says("opacc6.nopasswd_all", "where", where)})
			case undefinedAlias.MatchString(cmd):
				unknown = append(unknown, catalog.Says("opacc6.undefined_alias", "alias", cmd, "where", where))
			default:
				findings = append(findings, Finding{Point: "sudo:" + commandPath(cmd), Detail: catalog.Says("opacc6.nopasswd", "where", where)})
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
			findings = append(findings, Finding{Point: point, Detail: catalog.Says("opacc6.not_authenticate", "where", where)})
		case strings.HasPrefix(setting, "timestamp_timeout="):
			if n, err := strconv.ParseFloat(strings.TrimPrefix(setting, "timestamp_timeout="), 64); err == nil && n < 0 {
				findings = append(findings, Finding{Point: point, Detail: catalog.Says("opacc6.cached_forever", "where", where)})
			}
		}
	}

	return findings, unknown
}

func commandPath(cmd string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	return path
}

func suFindings(pam PAM) (findings []Finding, unknown []catalog.Message) {

	if gap, found := pam.Gap(); found {
		return nil, []catalog.Message{catalog.Says("item.name_detail", "name", "su", "detail", gap.Message)}
	}

	for _, service := range []string{"su", "su-l"} {
		for _, r := range pam.Stack(service, "auth") {
			if _, trust := Arg(r, "trust"); r.Module == "pam_wheel.so" && trust {
				findings = append(findings, Finding{Point: "su", Detail: catalog.Says("opacc6.wheel_trust", "file", r.File, "line", r.Line)})
			}
		}
	}

	return findings, nil
}

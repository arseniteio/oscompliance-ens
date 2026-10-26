package opacc6

import (
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

const (
	ExposureVersion      = "sshd:version_software"
	ExposureDistribution = "sshd:version_distribucion"
	ExposureAddendum     = "sshd:version_addendum"
	ExposureBanner       = "sshd:banner_previo"
)

type EV12Input struct {
	Settings Settings

	Allowed        []string
	AllowedProblem string
}

func JudgeEV12(in EV12Input) verdict.Judgement {

	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.AllowedProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-11: "+in.AllowedProblem)
	}

	sshd := in.Settings.SSHD()

	switch sshd.Status {
	case fact.SourceAbsent:
		return verdict.Judgement{Status: verdict.Compliant, Reason: "sshd not installed: no authentication service shows anything"}
	case fact.SourceRead:
	case "":
		return passes.NotEvaluable(verdict.CauseCollection, "the configuration read has no sshd -T")
	default:
		return passes.NotEvaluable(verdict.CauseCollection, "sshd -T: "+sshd.Error)
	}

	exposures := []string{ExposureVersion}

	version := ""
	if v, ok := in.Settings.Command(" -V"); ok && v.Status == fact.SourceRead && len(v.Entries) > 0 {
		version = v.Entries[0].Value
	}

	if banner := sshd.Get("debianbanner"); banner == "yes" || (banner == "" && (strings.Contains(version, "Ubuntu") || strings.Contains(version, "Debian"))) {
		exposures = append(exposures, ExposureDistribution)
	}
	if v := sshd.Get("versionaddendum"); v != "" && v != "none" {
		exposures = append(exposures, ExposureAddendum)
	}
	if v := sshd.Get("banner"); v != "" && v != "none" {
		exposures = append(exposures, ExposureBanner)
	}

	allowed := map[string]bool{}
	for _, a := range in.Allowed {
		allowed[strings.TrimSpace(a)] = true
	}

	var shown []string
	for _, e := range exposures {
		if !allowed[e] {
			shown = append(shown, e)
		}
	}

	if len(shown) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "shown before authenticating and not in P-11: " + strings.Join(shown, ", ")}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: "sshd shows only what P-11 allows: " + strings.Join(exposures, ", ")}
}

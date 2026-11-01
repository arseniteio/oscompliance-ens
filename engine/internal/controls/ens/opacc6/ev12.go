package opacc6

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
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
	AllowedProblem catalog.Message
}

func JudgeEV12(in EV12Input) verdict.Judgement {

	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if !in.AllowedProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.AllowedProblem)
	}

	sshd := in.Settings.SSHD()

	switch sshd.Status {
	case fact.SourceAbsent:
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.sshd_not_installed_no_authentication_ser"))
	case fact.SourceRead:
	case "":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.the_configuration_read_has_no_sshd_t"))
	default:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.sshd_t_a", "a", sshd.Error))
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
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.shown_before_authenticating_and_not_in_p", "a", shown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.sshd_shows_only_what_p_11_allows_a", "a", exposures))
}

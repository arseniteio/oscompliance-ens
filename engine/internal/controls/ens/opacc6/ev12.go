package opacc6

import (
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// Exposures named as P-11 names them.
const (
	ExposureVersion      = "sshd:version_software"
	ExposureDistribution = "sshd:version_distribucion"
	ExposureAddendum     = "sshd:version_addendum"
	ExposureBanner       = "sshd:banner_previo"
)

// EV12Input is what EV-12 (information shown before authenticating) needs.
type EV12Input struct {
	Settings Settings

	// Allowed is P-11 ("ninguna" for none); AllowedProblem says why it
	// cannot be used.
	Allowed        []string
	AllowedProblem string
}

// JudgeEV12 judges EV-12 as described in catalog/docs/contracts/op.acc.6.md,
// from the configuration only: no connection is opened.
//
//  1. Configuration unusable: NOT_EVALUABLE, COLLECTION. P-11 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. sshd not installed: COMPLIANT, nothing is shown. sshd -T not read:
//     NOT_EVALUABLE, COLLECTION.
//  3. Exposures: the software version (always, the protocol sends it), the
//     distribution in it (DebianBanner, on by default in Debian builds), a
//     VersionAddendum, a Banner shown before login.
//  4. An exposure not in P-11: NON_COMPLIANT. Otherwise COMPLIANT.
func JudgeEV12(in EV12Input) verdict.Judgement {

	// 1. Facts and parameter.
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.AllowedProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-11: "+in.AllowedProblem)
	}

	// 2. Is there a server at all.
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

	// 3. What sshd shows.
	exposures := []string{ExposureVersion}

	version := ""
	if v, ok := in.Settings.Command(" -V"); ok && v.Status == fact.SourceRead && len(v.Entries) > 0 {
		version = v.Entries[0].Value
	}

	// Debian and Ubuntu patch the version string with the distribution
	// unless DebianBanner is off; sshd -T only prints the option there.
	if banner := sshd.Get("debianbanner"); banner == "yes" || (banner == "" && (strings.Contains(version, "Ubuntu") || strings.Contains(version, "Debian"))) {
		exposures = append(exposures, ExposureDistribution)
	}
	if v := sshd.Get("versionaddendum"); v != "" && v != "none" {
		exposures = append(exposures, ExposureAddendum)
	}
	if v := sshd.Get("banner"); v != "" && v != "none" {
		exposures = append(exposures, ExposureBanner)
	}

	// 4. Against P-11.
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

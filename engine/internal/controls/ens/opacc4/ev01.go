// Package opacc4 judges op.acc.4 (management of access rights): what is
// open to anyone, who holds which privileges against the matrix of P-01,
// who changes rights, who reaches need-to-know resources, and whether
// rights are reviewed.
package opacc4

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/controls/ens/opacc6"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV01Input is what EV-01 (deny by default) needs.
type EV01Input struct {
	Firewall *fact.FirewallSnapshot
	Settings opacc6.Settings

	// Resources is the recurso column of P-01: the openings authorised.
	Resources        []string
	ResourcesProblem string
}

// Opening is something that admits anyone unless told otherwise.
type Opening struct {
	Resource string
	Detail   string
}

// JudgeEV01 judges EV-01 as described in catalog/docs/contracts/op.acc.4.md:
//
//  1. Firewall or configuration facts unusable: NOT_EVALUABLE, COLLECTION.
//  2. Openings: the packet filter accepts by default on input or forward,
//     or there is none (no base input chain accepts everything; v1 passed a
//     machine with an empty ruleset); a Samba share open to guests; vsftpd
//     with anonymous access.
//  3. An opening whose resource is not in the recurso column of P-01:
//     NON_COMPLIANT. Openings with P-01 unusable: NOT_EVALUABLE,
//     CONFIGURATION.
//  4. Otherwise COMPLIANT.
func JudgeEV01(in EV01Input) verdict.Judgement {

	// 1. Facts.
	switch {
	case in.Firewall == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no firewall_snapshot in the window")
	case in.Firewall.Status != fact.SourceRead:
		return passes.NotEvaluable(verdict.CauseCollection, in.Firewall.Tool+" could not be read: "+in.Firewall.Error)
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}

	// 2. What is open.
	openings, unreadable := Openings(*in.Firewall, in.Settings)
	if len(unreadable) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unreadable, "; "))
	}
	if len(openings) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "the packet filter denies by default and nothing admits anonymous access"}
	}

	// 3. Against P-01.
	if in.ResourcesProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-01: "+in.ResourcesProblem)
	}

	authorised := map[string]bool{}
	for _, r := range in.Resources {
		authorised[strings.TrimSpace(r)] = true
	}

	var open, allowed []string
	for _, o := range openings {
		item := o.Resource + ": " + o.Detail
		if authorised[o.Resource] {
			allowed = append(allowed, item)
		} else {
			open = append(open, item)
		}
	}

	if len(open) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "open by default and not authorised in P-01: " + strings.Join(open, "; ")}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: "every opening is authorised in P-01: " + strings.Join(allowed, "; ")}
}

// Openings lists what admits anyone; unreadable lists the sources that
// could not be read.
func Openings(fw fact.FirewallSnapshot, settings opacc6.Settings) (openings []Opening, unreadable []string) {

	// The packet filter.
	switch fw.Tool {
	case "none":
		openings = append(openings, Opening{"cortafuegos", "no packet filter installed: everything is accepted"})
	default:
		input := false
		for _, c := range fw.Chains {
			if c.Hook == "input" {
				input = true
			}
			if c.Policy == "accept" {
				openings = append(openings, Opening{"cortafuegos", fmt.Sprintf("%s %s %s chain %s accepts by default", fw.Tool, c.Family, c.Hook, c.Name)})
			}
		}
		if !input {
			openings = append(openings, Opening{"cortafuegos", fw.Tool + " has no input chain: everything is accepted"})
		}
	}

	// Samba shares open to guests.
	for _, f := range settings.Files {

		switch {
		case f.Source != "/etc/samba/smb.conf" && f.Source != "/etc/vsftpd.conf":
			continue
		case f.Status == fact.SourceAbsent:
			continue
		case f.Status != fact.SourceRead:
			unreadable = append(unreadable, f.Source+": "+f.Error)
			continue
		}

		shares := map[string]bool{}
		for _, e := range f.Entries {

			key := strings.ToLower(strings.Join(strings.Fields(e.Key), " "))
			yes := truthy(e.Value)

			switch {
			case f.Source == "/etc/vsftpd.conf" && strings.EqualFold(e.Key, "anonymous_enable") && yes:
				openings = append(openings, Opening{"vsftpd", "anonymous_enable=" + e.Value})
			case f.Source == "/etc/samba/smb.conf" && !strings.EqualFold(e.Section, "global") && (key == "guest ok" || key == "public") && yes && !shares[e.Section]:
				shares[e.Section] = true
				openings = append(openings, Opening{e.Section, "Samba share with " + key + " = " + e.Value})
			}
		}
	}

	sort.SliceStable(openings, func(i, j int) bool { return openings[i].Resource < openings[j].Resource })
	return openings, unreadable
}

// truthy: Samba and vsftpd booleans (yes, true, 1).
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1":
		return true
	}
	return false
}

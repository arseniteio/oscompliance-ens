package opacc4

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV01Input struct {
	Firewall *fact.FirewallSnapshot
	Settings opacc6.Settings

	Resources        []string
	ResourcesProblem string
}

type Opening struct {
	Resource string
	Detail   string
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	switch {
	case in.Firewall == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no firewall_snapshot in the window")
	case in.Firewall.Status != fact.SourceRead:
		return passes.NotEvaluable(verdict.CauseCollection, in.Firewall.Tool+" could not be read: "+in.Firewall.Error)
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}

	openings, unreadable := Openings(*in.Firewall, in.Settings)
	if len(unreadable) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unreadable, "; "))
	}
	if len(openings) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "the packet filter denies by default and nothing admits anonymous access"}
	}

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

func Openings(fw fact.FirewallSnapshot, settings opacc6.Settings) (openings []Opening, unreadable []string) {

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

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "true", "1":
		return true
	}
	return false
}

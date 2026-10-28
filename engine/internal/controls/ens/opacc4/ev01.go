package opacc4

import (
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV01Input struct {
	Firewall *fact.FirewallSnapshot
	Settings opacc6.Settings

	Resources        []string
	ResourcesProblem catalog.Message
}

type Opening struct {
	Resource string
	Detail   catalog.Message
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	switch {
	case in.Firewall == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.no_firewall_snapshot_in_the_window"))
	case in.Firewall.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc4.a_could_not_be_read_b", "a", in.Firewall.Tool, "b", in.Firewall.Error))
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}

	openings, unreadable := Openings(*in.Firewall, in.Settings)
	if len(unreadable) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings", "list", unreadable))
	}
	if len(openings) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.the_packet_filter_denies_by_default_and"))
	}

	if !in.ResourcesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ResourcesProblem)
	}

	authorised := map[string]bool{}
	for _, r := range in.Resources {
		authorised[strings.TrimSpace(r)] = true
	}

	var open, allowed []catalog.Message
	for _, o := range openings {
		item := catalog.Says("item.name_detail", "name", o.Resource, "detail", o.Detail)
		if authorised[o.Resource] {
			allowed = append(allowed, item)
		} else {
			open = append(open, item)
		}
	}

	if len(open) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc4.open_by_default_and_not_authorised_in_p", "a", open))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc4.every_opening_is_authorised_in_p_01_a", "a", allowed))
}

func Openings(fw fact.FirewallSnapshot, settings opacc6.Settings) (openings []Opening, unreadable []catalog.Message) {

	switch fw.Tool {
	case "none":
		openings = append(openings, Opening{"cortafuegos", catalog.Says("opacc4.no_filter")})
	default:
		input := false
		for _, c := range fw.Chains {
			if c.Hook == "input" {
				input = true
			}
			if c.Policy == "accept" {
				openings = append(openings, Opening{"cortafuegos", catalog.Says("opacc4.chain_accepts", "tool", fw.Tool, "family", c.Family, "hook", c.Hook, "chain", c.Name)})
			}
		}
		if !input {
			openings = append(openings, Opening{"cortafuegos", catalog.Says("opacc4.no_input_chain", "tool", fw.Tool)})
		}
	}

	for _, f := range settings.Files {

		switch {
		case f.Source != "/etc/samba/smb.conf" && f.Source != "/etc/vsftpd.conf":
			continue
		case f.Status == fact.SourceAbsent:
			continue
		case f.Status != fact.SourceRead:
			unreadable = append(unreadable, catalog.Says("item.error", "path", f.Source, "error", f.Error))
			continue
		}

		shares := map[string]bool{}
		for _, e := range f.Entries {

			key := strings.ToLower(strings.Join(strings.Fields(e.Key), " "))
			yes := truthy(e.Value)

			switch {
			case f.Source == "/etc/vsftpd.conf" && strings.EqualFold(e.Key, "anonymous_enable") && yes:
				openings = append(openings, Opening{"vsftpd", catalog.Says("opacc4.ftp_anonymous", "value", e.Value)})
			case f.Source == "/etc/samba/smb.conf" && !strings.EqualFold(e.Section, "global") && (key == "guest ok" || key == "public") && yes && !shares[e.Section]:
				shares[e.Section] = true
				openings = append(openings, Opening{e.Section, catalog.Says("opacc4.samba_guest", "key", key, "value", e.Value)})
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

package opacc6

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

var channels = map[string]string{source.MethodSSHD: "ssh"}

type EV07Input struct {
	Logins []source.Login

	Log passes.AuthLog

	Channels        []string
	ChannelsProblem string
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if in.ChannelsProblem != "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc6.p_07_a", "a", in.ChannelsProblem))
	}

	authorized := map[string]bool{}
	for _, c := range in.Channels {
		authorized[strings.ToLower(strings.TrimSpace(c))] = true
	}

	used := map[string]int{}
	outside := map[string]int{}

	for _, l := range in.Logins {

		channel, remote := channels[l.Method]
		if !remote {
			continue
		}

		used[channel]++
		if !authorized[channel] {
			outside[fmt.Sprintf("%s by %s from %s", channel, l.Account, l.SourceIP)]++
		}
	}

	if len(outside) > 0 {
		var list []string
		for k, n := range outside {
			list = append(list, fmt.Sprintf("%s (%d)", k, n))
		}
		sort.Strings(list)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.remote_logins_through_channels_not_in_p", "a", list))
	}

	if len(used) == 0 {
		if !in.Log.Reaches {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.remote_logins_cannot_be_seen_a", "a", in.Log.Detail))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_remote_login_in_the_window"))
	}

	var list []string
	for c, n := range used {
		list = append(list, fmt.Sprintf("%s (%d logins)", c, n))
	}
	sort.Strings(list)

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.remote_logins_only_through_p_07_channels", "a", list))
}

package opacc6

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var channels = map[string]string{source.MethodSSHD: "ssh"}

type EV07Input struct {
	Logins []source.Login

	Log passes.AuthLog

	Channels        []string
	ChannelsProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if !in.ChannelsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ChannelsProblem)
	}

	authorized := map[string]bool{}
	for _, c := range in.Channels {
		authorized[strings.ToLower(strings.TrimSpace(c))] = true
	}

	used := map[string]int{}
	outside := map[[3]string]int{}

	for _, l := range in.Logins {

		channel, remote := channels[l.Method]
		if !remote {
			continue
		}

		used[channel]++
		if !authorized[channel] {
			outside[[3]string{channel, l.Account, l.SourceIP}]++
		}
	}

	if len(outside) > 0 {
		var list []catalog.Message
		for k, n := range outside {
			list = append(list, catalog.Says("opacc6.login_through", "channel", k[0], "account", k[1], "ip", k[2], "count", n))
		}
		catalog.SortMessages(list)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.remote_logins_through_channels_not_in_p", "a", list))
	}

	if len(used) == 0 {
		if !in.Log.Reaches {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.remote_logins_cannot_be_seen_a", "a", in.Log.Detail))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_remote_login_in_the_window"))
	}

	var list []catalog.Message
	for c, n := range used {
		list = append(list, catalog.Says("opacc6.channel_logins", "channel", c, "count", n))
	}
	catalog.SortMessages(list)

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.remote_logins_only_through_p_07_channels", "a", list))
}

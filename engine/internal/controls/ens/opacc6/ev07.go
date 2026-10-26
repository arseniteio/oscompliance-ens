package opacc6

import (
	"fmt"
	"sort"
	"strings"

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
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-07: "+in.ChannelsProblem)
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
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "remote logins through channels not in P-07: " + strings.Join(list, "; ")}
	}

	if len(used) == 0 {
		if !in.Log.Reaches {
			return passes.NotEvaluable(verdict.CauseCollection, "remote logins cannot be seen: "+in.Log.Detail)
		}
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no remote login in the window"}
	}

	var list []string
	for c, n := range used {
		list = append(list, fmt.Sprintf("%s (%d logins)", c, n))
	}
	sort.Strings(list)

	return verdict.Judgement{Status: verdict.Compliant, Reason: "remote logins only through P-07 channels: " + strings.Join(list, ", ")}
}

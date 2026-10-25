package opacc6

import (
	"fmt"
	"sort"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// channels names each remote login method as P-07 names channels.
var channels = map[string]string{source.MethodSSHD: "ssh"}

// EV07Input is what EV-07 (remote access through authorized channels) needs.
type EV07Input struct {
	// Logins in the window, as Wazuh decoded them.
	Logins []source.Login
	// Log: when the authentication log does not reach Wazuh, an empty
	// Logins proves nothing.
	Log AuthLog

	// Channels is the canal column of P-07; ChannelsProblem says why it
	// cannot be used.
	Channels        []string
	ChannelsProblem string
}

// JudgeEV07 judges EV-07 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. P-07 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. A remote login through a channel not in P-07 (case-insensitive):
//     NON_COMPLIANT.
//  3. No remote login while the authentication log is not known to reach
//     Wazuh: NOT_EVALUABLE, COLLECTION.
//  4. Otherwise COMPLIANT.
func JudgeEV07(in EV07Input) verdict.Judgement {

	// 1. Parameter.
	if in.ChannelsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-07: "+in.ChannelsProblem)
	}

	authorized := map[string]bool{}
	for _, c := range in.Channels {
		authorized[strings.ToLower(strings.TrimSpace(c))] = true
	}

	// 2. Every remote login.
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

	// 3. Silence proves nothing when the log does not arrive.
	if len(used) == 0 {
		if !in.Log.Reaches {
			return passes.NotEvaluable(verdict.CauseCollection, "remote logins cannot be seen: "+in.Log.Detail)
		}
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no remote login in the window"}
	}

	// 4. Every channel used is authorized.
	var list []string
	for c, n := range used {
		list = append(list, fmt.Sprintf("%s (%d logins)", c, n))
	}
	sort.Strings(list)

	return verdict.Judgement{Status: verdict.Compliant, Reason: "remote logins only through P-07 channels: " + strings.Join(list, ", ")}
}

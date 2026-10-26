package opacc6

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// RegisterParam is the register of compromised credentials and people who
// left, "usuario | fecha | motivo" (motivo: compromiso or baja). The plugin
// does not offer it yet; v1 read a file on every machine instead.
const RegisterParam = "P-12"

// Notice is one register row.
type Notice struct {
	Account string
	At      time.Time
	Reason  string
}

// ParseRegister reads the register rows. The date is RFC 3339, or a day
// (YYYY-MM-DD, taken as 00:00 UTC: the earliest it can mean).
func ParseRegister(rows []string) ([]Notice, string) {

	var out []Notice

	for _, row := range rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) < 2 || cells[0] == "" {
			return nil, fmt.Sprintf("row %q: want usuario | fecha | motivo", row)
		}

		at, err := time.Parse(time.RFC3339, cells[1])
		if err != nil {
			if at, err = time.Parse("2006-01-02", cells[1]); err != nil {
				return nil, fmt.Sprintf("row %q: %q is not a date", row, cells[1])
			}
		}

		n := Notice{Account: cells[0], At: at}
		if len(cells) > 2 {
			n.Reason = cells[2]
		}
		out = append(out, n)
	}

	return out, ""
}

// EV06Input is what EV-06 (disablement after compromise or leaving) needs.
type EV06Input struct {
	// History is the account history op.acc.1 keeps for the agent.
	History map[string]history.Account
	Now     time.Time

	Notices        []Notice
	NoticesProblem string

	// MaxHours is P-06; MaxHoursProblem says why it cannot be used.
	MaxHours        int
	MaxHoursProblem string
}

// JudgeEV06 judges EV-06 as described in catalog/docs/contracts/op.acc.6.md,
// for each notice of an account this machine has:
//
//  1. Register or P-06 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Disabled or deleted: the hours from the notice to the first pass that
//     saw it so (an account already disabled before the notice took 0).
//     Still enabled: the hours since the notice.
//  3. More than P-06: NON_COMPLIANT.
//  4. Disabled when the engine first saw the account, after the notice:
//     only an upper bound is known; within P-06 it counts as on time, beyond
//     it NOT_EVALUABLE, EVIDENCE (v1 blocked on every such case).
//  5. Otherwise COMPLIANT, also with no notice for this machine.
func JudgeEV06(in EV06Input) verdict.Judgement {

	// 1. Parameters.
	if in.NoticesProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, RegisterParam+" (register of compromised and departed accounts): "+in.NoticesProblem)
	}
	if in.MaxHoursProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-06: "+in.MaxHoursProblem)
	}

	limit := time.Duration(in.MaxHours) * time.Hour
	var late, unknown, onTime []string

	for _, n := range in.Notices {

		a, here := in.History[n.Account]
		if !here {
			continue
		}

		// 2. When it stopped being usable.
		var end *time.Time
		switch {
		case a.DeletedAt != nil:
			end = a.DeletedAt
		case a.DisabledSince != nil:
			end = a.DisabledSince
		}

		where := fmt.Sprintf("%s (%s %s)", n.Account, n.Reason, n.At.UTC().Format(time.RFC3339))

		switch {
		case end == nil:
			if took := in.Now.Sub(n.At); took > limit {
				late = append(late, fmt.Sprintf("%s: still enabled after %d hours", where, int(took.Hours())))
			} else {
				onTime = append(onTime, where+": within the deadline, not disabled yet")
			}
		case !end.After(n.At):
			onTime = append(onTime, where+": already disabled")
		case a.DeletedAt == nil && !a.DisabledObserved:
			// 4. Disabled when first seen: it took at most this long.
			if took := end.Sub(n.At); took > limit {
				unknown = append(unknown, fmt.Sprintf("%s: disabled within %d hours, when it took is unknown", where, int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		default:
			// 3. Measured.
			if took := end.Sub(n.At); took > limit {
				late = append(late, fmt.Sprintf("%s: disabled after %d hours", where, int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		}
	}

	if len(late) > 0 {
		sort.Strings(late)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: fmt.Sprintf("not disabled within %d hours: %s", in.MaxHours, strings.Join(late, "; "))}
	}

	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	// 5. On time.
	if len(onTime) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no notice in the register for an account of this machine"}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("disabled within %d hours of the notice: %s", in.MaxHours, strings.Join(onTime, "; "))}
}

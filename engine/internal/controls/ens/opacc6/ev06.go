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

const RegisterParam = "P-12"

type Notice struct {
	Account string
	At      time.Time
	Reason  string
}

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

type EV06Input struct {
	History map[string]history.Account
	Now     time.Time

	Notices        []Notice
	NoticesProblem string

	MaxHours        int
	MaxHoursProblem string
}

func JudgeEV06(in EV06Input) verdict.Judgement {

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

			if took := end.Sub(n.At); took > limit {
				unknown = append(unknown, fmt.Sprintf("%s: disabled within %d hours, when it took is unknown", where, int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		default:

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

	if len(onTime) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no notice in the register for an account of this machine"}
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("disabled within %d hours of the notice: %s", in.MaxHours, strings.Join(onTime, "; "))}
}

package opacc6

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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

func ParseRegister(rows []string) ([]Notice, catalog.Message) {

	var out []Notice

	for _, row := range rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) < 2 || cells[0] == "" {
			return nil, catalog.Says("opacc6.register_row", "param", RegisterParam, "row", row)
		}

		at, err := time.Parse(time.RFC3339, cells[1])
		if err != nil {
			if at, err = time.Parse("2006-01-02", cells[1]); err != nil {
				return nil, catalog.Says("opacc6.register_date", "param", RegisterParam, "row", row, "value", cells[1])
			}
		}

		n := Notice{Account: cells[0], At: at}
		if len(cells) > 2 {
			n.Reason = cells[2]
		}
		out = append(out, n)
	}

	return out, catalog.Message{}
}

type EV06Input struct {
	History map[string]history.Account
	Now     time.Time

	Notices        []Notice
	NoticesProblem catalog.Message

	MaxHours        int
	MaxHoursProblem catalog.Message
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.NoticesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.NoticesProblem)
	}
	if !in.MaxHoursProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxHoursProblem)
	}

	limit := time.Duration(in.MaxHours) * time.Hour
	var late, unknown, onTime []catalog.Message

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

		where := catalog.Raw(fmt.Sprintf("%s (%s %s)", n.Account, n.Reason, n.At.UTC().Format(time.RFC3339)))

		switch {
		case end == nil:
			if took := in.Now.Sub(n.At); took > limit {
				late = append(late, catalog.Says("opacc6.still_enabled", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, catalog.Says("opacc6.within_deadline", "notice", where))
			}
		case !end.After(n.At):
			onTime = append(onTime, catalog.Says("opacc6.already_disabled", "notice", where))
		case a.DeletedAt == nil && !a.DisabledObserved:

			if took := end.Sub(n.At); took > limit {
				unknown = append(unknown, catalog.Says("opacc6.disabled_when_unknown", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		default:

			if took := end.Sub(n.At); took > limit {
				late = append(late, catalog.Says("opacc6.disabled_after", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		}
	}

	if len(late) > 0 {
		catalog.SortMessages(late)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.not_disabled_within_a_hours_b", "a", in.MaxHours, "b", late))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	if len(onTime) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_notice_in_the_register_for_an_account"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.disabled_within_a_hours_of_the_notice_b", "a", in.MaxHours, "b", onTime))
}

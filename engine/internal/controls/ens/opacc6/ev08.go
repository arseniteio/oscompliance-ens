package opacc6

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV08Input struct {
	Listening Listening

	Rows        []string
	RowsProblem string
}

type channelRow struct {
	encrypted string
	constant  string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if gap, found := in.Listening.Gap(); found {
		return gap
	}
	if in.RowsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-07: "+in.RowsProblem)
	}

	rows := map[string]channelRow{}
	for _, r := range in.Rows {
		cells := strings.Split(r, "|")
		for i := range cells {
			cells[i] = strings.ToLower(strings.TrimSpace(cells[i]))
		}
		for len(cells) < 4 {
			cells = append(cells, "")
		}
		rows[cells[0]] = channelRow{encrypted: cells[1], constant: cells[3]}
	}

	channels, other := in.Listening.Channels()

	var failing, unknown, fine []string

	for _, c := range channels {

		where := fmt.Sprintf("%s (%s on %v)", c.Name, strings.Join(c.Processes, ","), c.Ports)
		row, listed := rows[c.Name]

		switch {
		case !listed:
			failing = append(failing, where+": no P-07 row")
			continue
		case !c.Encrypted:
			failing = append(failing, where+": not encrypted")
			continue
		}

		if row.constant == "no" {
			switch state := enablement(c); state {
			case "enabled":
				failing = append(failing, where+": enabled at boot, P-07 says it is not of constant use")
				continue
			case "":
				unknown = append(unknown, where+": whether it starts at boot is unknown")
				continue
			}
		}

		fine = append(fine, c.Name)
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}

	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	reason := "no remote access channel listening"
	if len(fine) > 0 {
		reason = "listening channels encrypted and as declared in P-07: " + strings.Join(fine, ", ")
	}
	if len(other) > 0 {
		reason += fmt.Sprintf("; %d other listeners are not access channels", len(other))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

func enablement(c Channel) string {

	if len(c.Units) == 0 {
		return ""
	}

	state := "disabled"

	for _, e := range c.Enabled {
		switch e {
		case "enabled", "enabled-runtime", "alias", "linked", "linked-runtime":
			return "enabled"
		case "disabled", "masked", "masked-runtime", "static", "indirect", "generated", "transient":
		default:
			state = ""
		}
	}

	return state
}

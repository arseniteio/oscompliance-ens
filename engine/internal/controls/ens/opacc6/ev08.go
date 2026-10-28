package opacc6

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV08Input struct {
	Listening Listening

	Rows        []string
	RowsProblem catalog.Message
}

type channelRow struct {
	encrypted string
	constant  string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if gap, found := in.Listening.Gap(); found {
		return gap
	}
	if !in.RowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.RowsProblem)
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

	var failing, unknown []catalog.Message
	var fine []string

	for _, c := range channels {

		where := catalog.Says("opacc6.channel_where", "name", c.Name, "processes", strings.Join(c.Processes, ","), "ports", fmt.Sprint(c.Ports))
		row, listed := rows[c.Name]

		switch {
		case !listed:
			failing = append(failing, catalog.Says("opacc6.no_p07_row", "channel", where))
			continue
		case !c.Encrypted:
			failing = append(failing, catalog.Says("opacc6.not_encrypted", "channel", where))
			continue
		}

		if row.constant == "no" {
			switch state := enablement(c); state {
			case "enabled":
				failing = append(failing, catalog.Says("opacc6.enabled_at_boot", "channel", where))
				continue
			case "":
				unknown = append(unknown, catalog.Says("opacc6.boot_unknown", "channel", where))
				continue
			}
		}

		fine = append(fine, c.Name)
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	reason := catalog.Says("opacc6.no_channel_listening")
	if len(fine) > 0 {
		reason = catalog.Says("opacc6.channels_fine", "list", fine)
	}
	if len(other) > 0 {
		reason = catalog.Says("opacc6.other_listeners", "reason", reason, "count", len(other))
	}

	return verdict.Explain(verdict.Compliant, "", reason)
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

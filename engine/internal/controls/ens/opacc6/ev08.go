package opacc6

import (
	"fmt"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// EV08Input is what EV-08 (listening channels: encrypted, enabled only when
// needed) needs.
type EV08Input struct {
	Listening Listening

	// Rows is P-07, "canal | cifrado | autoriza | uso_constante";
	// RowsProblem says why it cannot be used.
	Rows        []string
	RowsProblem string
}

// channelRow is one P-07 row.
type channelRow struct {
	encrypted string // si, no
	constant  string // si: may stay enabled; no: enabled only when needed
}

// JudgeEV08 judges EV-08 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. Sockets unusable: NOT_EVALUABLE, COLLECTION. P-07 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. Each remote access channel listening, from its process or unit
//     (ssh, rdp, vnc, telnet, ftp, ldap, cockpit, webmin, openvpn,
//     tailscale); other listeners are not access channels.
//  3. NON_COMPLIANT: a channel without a P-07 row (P-07 says a channel
//     without a row is not accepted), a channel that does not encrypt (the
//     ENS asks remote access to be encrypted, whatever the row declares),
//     or a channel enabled at boot when its row says it is not of constant
//     use. A row saying constant use allows both states (v1 demanded it to
//     be enabled).
//  4. Enablement unknown where the row needs it (no systemd):
//     NOT_EVALUABLE, EVIDENCE.
//  5. Otherwise COMPLIANT, also when no channel listens.
func JudgeEV08(in EV08Input) verdict.Judgement {

	// 1. Facts and parameter.
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

	// 2. The channels.
	channels, other := in.Listening.Channels()

	var failing, unknown, fine []string

	for _, c := range channels {

		where := fmt.Sprintf("%s (%s on %v)", c.Name, strings.Join(c.Processes, ","), c.Ports)
		row, listed := rows[c.Name]

		// 3. The failures.
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

	// 4. What could not be told.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseEvidence, strings.Join(unknown, "; "))
	}

	// 5. Every channel as declared.
	reason := "no remote access channel listening"
	if len(fine) > 0 {
		reason = "listening channels encrypted and as declared in P-07: " + strings.Join(fine, ", ")
	}
	if len(other) > 0 {
		reason += fmt.Sprintf("; %d other listeners are not access channels", len(other))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: reason}
}

// enablement is "enabled" when any unit of the channel starts at boot,
// "disabled" when every one is known not to, "" when it is not known.
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

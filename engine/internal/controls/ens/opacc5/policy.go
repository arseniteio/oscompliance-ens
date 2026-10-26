package opacc5

import (
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
)

// Policy is the newest "politica" line of a service: its lockout and
// password policy as it declares them.
type Policy struct {
	Service string
	Found   bool

	Lockout      string // activado, desactivado, "" not declared
	MaxAttempts  int    // 0: not a number or not declared
	Reactivation string // intervencion, automatica, ""

	MinLength  int    // 0: not declared
	Complexity string // activada, desactivada, ""
}

// Policies takes the newest politica event of each service.
func Policies(events []source.ServiceEvent) map[string]Policy {

	out := map[string]Policy{}

	for _, e := range events {

		if e.Tipo != "politica" {
			continue
		}

		p := Policy{Service: e.Service, Found: true,
			Lockout: strings.ToLower(e.Bloqueo), Reactivation: strings.ToLower(e.Reactivacion), Complexity: strings.ToLower(e.Complejidad)}

		if n, err := strconv.Atoi(e.MaxIntentos); err == nil {
			p.MaxAttempts = n
		}
		if n, err := strconv.Atoi(e.LongitudMinima); err == nil {
			p.MinLength = n
		}

		// A max of 0 is no limit: lockout off.
		if p.Lockout == "activado" && e.MaxIntentos == "0" {
			p.Lockout = "desactivado"
		}

		// Events come oldest first: the last one wins.
		out[e.Service] = p
	}

	return out
}

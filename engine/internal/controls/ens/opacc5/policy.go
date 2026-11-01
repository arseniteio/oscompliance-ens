package opacc5

import (
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
)

type Policy struct {
	Service string
	Found   bool

	Lockout      string
	MaxAttempts  int
	Reactivation string

	MinLength  int
	Complexity string
}

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

		if p.Lockout == "activado" && e.MaxIntentos == "0" {
			p.Lockout = "desactivado"
		}

		out[e.Service] = p
	}

	return out
}

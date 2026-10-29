// Package opexp5 judges op.exp.5, change management: the changes that happen on each machine against the
// change register of P-10.
package opexp5

import (
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
)

// RegisterParam is the change register; op.exp.3 judges its configuration edits against it too.
const (
	Control       = "op.exp.5"
	RegisterParam = "P-10"
)

// The register is written in Spain's time unless a time carries its zone.
var madrid, _ = time.LoadLocation("Europe/Madrid")

// Request is one row of the change register.
type Request struct {
	ID, System, Description, Risk, ApprovedBy, Status, Documents, Impact string
	Registered, Approved, From, Until                                    time.Time
	Fields                                                               map[string]string
	Row                                                                  string
}

var columns = []string{"peticion", "fecha_registro", "sistema", "descripcion", "riesgo", "aprobado_por", "fecha_aprobacion", "ventana_inicio", "ventana_fin", "estado", "documentacion", "impacto_seguridad"}

// ParseRegister reads the rows of P-10; a date that cannot be read stays zero, which no window holds.
func ParseRegister(rows []string) []Request {
	var out []Request
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < len(columns) {
			c = append(c, "")
		}
		f := map[string]string{}
		for i, name := range columns {
			f[name] = strings.TrimSpace(c[i])
		}
		out = append(out, Request{
			ID: f["peticion"], System: f["sistema"], Description: f["descripcion"], Risk: strings.ToLower(f["riesgo"]),
			ApprovedBy: f["aprobado_por"], Status: strings.ToLower(f["estado"]), Documents: f["documentacion"], Impact: f["impacto_seguridad"],
			Registered: When(f["fecha_registro"]), Approved: When(f["fecha_aprobacion"]), From: When(f["ventana_inicio"]), Until: When(f["ventana_fin"]),
			Fields: f, Row: strings.TrimSpace(r),
		})
	}
	return out
}

// When reads `2026-10-20 06:00`, `2026-10-20` or RFC 3339.
func When(v string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, madrid); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Authorised says whether the request was approved and carried out, or is still in force.
func (r Request) Authorised() bool {
	return r.Status == "aprobada" || r.Status == "implantada" || r.Status == "revertida"
}

func (r Request) For(machine string) bool {
	return r.System == "*" || strings.EqualFold(r.System, machine)
}

// Covers says whether the request authorises a change of the machine at t.
func (r Request) Covers(machine string, t time.Time) bool {
	return r.For(machine) && r.Authorised() && !r.Approved.IsZero() && !r.Approved.After(t) &&
		!r.From.IsZero() && !t.Before(r.From) && (r.Until.IsZero() || !t.After(r.Until))
}

// Touches says whether the request's window reaches into the time since a moment.
func (r Request) Touches(since time.Time) bool {
	return !r.From.IsZero() && (r.Until.IsZero() || !r.Until.Before(since))
}

// Change is something that changed on the machine: a file Wazuh's FIM saw, or an apt transaction.
type Change struct {
	Time time.Time
	What string
}

func (c Change) String() string { return c.Time.UTC().Format("2006-01-02 15:04") + " " + c.What }

// Changes are the FIM changes and the apt transactions since a time, in order.
func Changes(fim []source.FIMChange, transactions []fact.PackageTransaction, since time.Time) []Change {
	var out []Change
	for _, f := range fim {
		if !f.Time.Before(since) {
			out = append(out, Change{Time: f.Time, What: f.Path + " (" + f.Event + ")"})
		}
	}
	for _, t := range transactions {
		start, err := time.Parse(time.RFC3339, t.Start)
		if err == nil && !start.Before(since) {
			out = append(out, Change{Time: start, What: fmt.Sprintf("apt %s (%s)", t.Command, t.Actor)})
		}
	}
	slices.SortFunc(out, func(a, b Change) int { return a.Time.Compare(b.Time) })
	return out
}

// Uncovered are the changes no request of the register authorises.
func Uncovered(changes []Change, requests []Request, machine string) []Change {
	var out []Change
	for _, c := range changes {
		if !slices.ContainsFunc(requests, func(r Request) bool { return r.Covers(machine, c.Time) }) {
			out = append(out, c)
		}
	}
	return out
}

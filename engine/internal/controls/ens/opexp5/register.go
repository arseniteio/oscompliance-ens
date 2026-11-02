package opexp5

import (
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
)

const (
	Control       = "op.exp.5"
	RegisterParam = "P-10"
)

var madrid, _ = time.LoadLocation("Europe/Madrid")

type Request struct {
	ID, System, Description, Risk, ApprovedBy, Status, Documents, Impact string
	Registered, Approved, From, Until                                    time.Time
	Fields                                                               map[string]string
	Row                                                                  string
}

var columns = []string{"peticion", "fecha_registro", "sistema", "descripcion", "riesgo", "aprobado_por", "fecha_aprobacion", "ventana_inicio", "ventana_fin", "estado", "documentacion", "impacto_seguridad"}

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

func When(v string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, madrid); err == nil {
			return t
		}
	}
	return time.Time{}
}

func (r Request) Authorised() bool {
	return r.Status == "aprobada" || r.Status == "implantada" || r.Status == "revertida"
}

func (r Request) For(machine string) bool {
	return r.System == "*" || strings.EqualFold(r.System, machine)
}

func (r Request) Covers(machine string, t time.Time) bool {
	return r.For(machine) && r.Authorised() && !r.Approved.IsZero() && !r.Approved.After(t) &&
		!r.From.IsZero() && !t.Before(r.From) && (r.Until.IsZero() || !t.After(r.Until))
}

func (r Request) Touches(since time.Time) bool {
	return !r.From.IsZero() && (r.Until.IsZero() || !r.Until.Before(since))
}

type Change struct {
	Time time.Time
	What string
}

func (c Change) String() string { return c.Time.UTC().Format("2006-01-02 15:04") + " " + c.What }

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

func Uncovered(changes []Change, requests []Request, machine string) []Change {
	var out []Change
	for _, c := range changes {
		if !slices.ContainsFunc(requests, func(r Request) bool { return r.Covers(machine, c.Time) }) {
			out = append(out, c)
		}
	}
	return out
}

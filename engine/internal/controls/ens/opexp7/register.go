package opexp7

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opexp5"
)

const (
	Control       = "op.exp.7"
	RegisterParam = "P-13"
)

const Horizon = 90 * 24 * time.Hour

type Phase struct {
	Name       string
	Date       time.Time
	Severity   string
	Systems    []string
	Class      string
	Escalated  string
	Notified   string
	Personal   string
	CCNCERT    string
	Legal      string
	Lessons    string
	Reference  string
	Review     time.Time
	ReviewText string
}

type Incident struct {
	ID     string
	Phases []Phase
}

var columns = []string{"incidente", "fase", "fecha", "severidad", "sistemas", "clasificacion", "escalado_a", "notificado_a", "datos_personales", "notificacion_ccn_cert", "relevancia_juridica", "medidas_mejora", "referencia", "revision_eventos"}

func empty(v string) bool { v = strings.TrimSpace(v); return v == "" || v == "-" }

func Severity(v string) string {
	return strings.NewReplacer("á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u").Replace(strings.ToLower(strings.TrimSpace(v)))
}

func ParseRegister(rows []string) []Incident {

	by := map[string]*Incident{}
	var order []string
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < len(columns) {
			c = append(c, "")
		}
		f := map[string]string{}
		for i, name := range columns {
			f[name] = strings.TrimSpace(c[i])
		}
		if f["incidente"] == "" {
			continue
		}
		var systems []string
		for _, s := range strings.Split(f["sistemas"], ",") {
			if s = strings.TrimSpace(s); !empty(s) {
				systems = append(systems, s)
			}
		}
		p := Phase{
			Name: strings.ToLower(f["fase"]), Date: opexp5.When(f["fecha"]), Severity: Severity(f["severidad"]), Systems: systems,
			Class: f["clasificacion"], Escalated: f["escalado_a"], Notified: f["notificado_a"], Personal: strings.ToLower(f["datos_personales"]),
			CCNCERT: f["notificacion_ccn_cert"], Legal: strings.ToLower(f["relevancia_juridica"]), Lessons: f["medidas_mejora"],
			Reference: f["referencia"], Review: opexp5.When(f["revision_eventos"]), ReviewText: f["revision_eventos"],
		}
		if by[f["incidente"]] == nil {
			by[f["incidente"]] = &Incident{ID: f["incidente"]}
			order = append(order, f["incidente"])
		}
		by[f["incidente"]].Phases = append(by[f["incidente"]].Phases, p)
	}

	out := make([]Incident, 0, len(order))
	for _, id := range order {
		in := by[id]
		slices.SortStableFunc(in.Phases, func(a, b Phase) int { return a.Date.Compare(b.Date) })
		out = append(out, *in)
	}
	return out
}

func (in Incident) phase(name string) (Phase, bool) {
	for _, p := range in.Phases {
		if p.Name == name {
			return p, true
		}
	}
	return Phase{}, false
}

func (in Incident) Opened() time.Time {
	if p, ok := in.phase("inicial"); ok && !p.Date.IsZero() {
		return p.Date
	}
	if len(in.Phases) > 0 {
		return in.Phases[0].Date
	}
	return time.Time{}
}

func (in Incident) Closed() time.Time {
	p, _ := in.phase("final")
	return p.Date
}

func (in Incident) Has(phase string) bool { _, ok := in.phase(phase); return ok }

func (in Incident) Severity() string {
	for i := len(in.Phases) - 1; i >= 0; i-- {
		if s := in.Phases[i].Severity; !empty(s) {
			return s
		}
	}
	return ""
}

func (in Incident) Any(f func(Phase) bool) bool { return slices.ContainsFunc(in.Phases, f) }

func (in Incident) Involves(machine string) bool {
	return in.Any(func(p Phase) bool {
		return slices.ContainsFunc(p.Systems, func(s string) bool { return s == "*" || strings.EqualFold(s, machine) })
	})
}

func (in Incident) Systems() []string {
	var out []string
	for _, p := range in.Phases {
		for _, s := range p.Systems {
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func (in Incident) Field(get func(Phase) string) string {
	for i := len(in.Phases) - 1; i >= 0; i-- {
		if v := get(in.Phases[i]); !empty(v) {
			return v
		}
	}
	return ""
}

func Of(incidents []Incident, machine string, now time.Time) []Incident {
	var out []Incident
	for _, in := range incidents {
		closed := in.Closed()
		if in.Involves(machine) && !in.Opened().IsZero() && (closed.IsZero() || now.Sub(closed) <= Horizon) {
			out = append(out, in)
		}
	}
	return out
}

func (in Incident) End(now time.Time) time.Time {
	if c := in.Closed(); !c.IsZero() {
		return c
	}
	return now
}

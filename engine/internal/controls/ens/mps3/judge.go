package mps3

import (
	"slices"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var Filters = []struct{ Name, Evidence string }{
	{"categorias", "EV-02"},
	{"descargas_y_contenido_activo", "EV-03"},
	{"reputacion", "EV-04"},
	{"lista_negra", "EV-10"},
	{"evasion", "EV-11"},
}

func JudgeEV05(d *fact.DeviceSecurity, authorised []string) verdict.Judgement {
	switch {
	case d == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.DeviceSecurityFact))
	case d.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("device", d.Status, d.Error))
	case len(d.Resolvers) == 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.no_resolvers"))
	}
	var other []string
	for _, r := range d.Resolvers {
		if !slices.ContainsFunc(authorised, func(a string) bool { return mpcom1.Match(a, r) && !mpcom1.Anywhere(a) }) {
			other = append(other, r)
		}
	}
	if len(other) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.resolvers_other", "list", other))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps3.resolvers", "list", d.Resolvers))
}

func JudgeEV08(days int, found bool, want int) verdict.Judgement {
	switch {
	case !found:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.no_retention"))
	case days < want:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.retention_short", "days", days, "min", want))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps3.retention", "days", days, "min", want))
}

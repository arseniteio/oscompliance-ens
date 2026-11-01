// Package mps3 judges mp.s.3, protection of web browsing: the logs of the browsing filter in Wazuh, its
// filters backed by loaded rules, the DNS servers each machine asks, the protection of the workstation, the
// retention of the browsing records, and the awareness and training of users and administrators.
package mps3

import (
	"slices"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// Filters of mp.s.3 as P-03 names them, and the evidence that judges each.
var Filters = []struct{ Name, Evidence string }{
	{"categorias", "EV-02"},
	{"descargas_y_contenido_activo", "EV-03"},
	{"reputacion", "EV-04"},
	{"lista_negra", "EV-10"},
	{"evasion", "EV-11"},
}

// JudgeEV05 needs every DNS server the machine asks among the authorised resolvers of P-04.
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

// JudgeEV08 needs the alerts, where the browsing records live, kept at least the days of P-08.
func JudgeEV08(days int, found bool, want int) verdict.Judgement {
	switch {
	case !found:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.no_retention"))
	case days < want:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps3.retention_short", "days", days, "min", want))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps3.retention", "days", days, "min", want))
}

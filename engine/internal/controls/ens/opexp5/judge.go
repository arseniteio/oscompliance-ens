package opexp5

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

// How far back the register is checked for complete and approved requests.
const RegisterHorizon = 90 * 24 * time.Hour

func list(changes []Change) []string {
	out := make([]string, len(changes))
	for i, c := range changes {
		out[i] = c.String()
	}
	if len(out) > 10 {
		out = append(out[:10], "…")
	}
	return out
}

// JudgeEV01 is the change detection itself: FIM watching and the apt history read.
func JudgeEV01(config *fact.WazuhAgentConfig, history *fact.TransactionSnapshot, changes []Change) verdict.Judgement {

	switch {
	case config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	case config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", config.Status, config.Error))
	case config.SyscheckDisabled:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.fim_disabled"))
	case history == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.TransactionSnapshotFact))
	case history.Status == fact.SourceUnreadable:
		return passes.Gap(verdict.CauseCollection, passes.Source("/var/log/apt/history.log", history.Status, history.Error))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.changes", "count", len(changes), "list", list(changes)))
}

func JudgeEV02(changes []Change, requests []Request, problem catalog.Message, machine string) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if bare := Uncovered(changes, requests, machine); len(bare) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.uncovered", "count", len(bare), "list", list(bare)))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.covered", "count", len(changes)))
}

// JudgeEV03 needs the columns of P-02, the prefix of P-01 and, at ALTA, the security impact in every
// authorised request of the machine.
func JudgeEV03(requests []Request, machine string, required []string, prefix string, high bool, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	var gaps []catalog.Message
	checked := 0
	for _, r := range requests {
		if !r.For(machine) || !r.Authorised() || !r.Touches(now.Add(-RegisterHorizon)) {
			continue
		}
		checked++
		var missing []catalog.Message
		for _, c := range required {
			if c = strings.TrimSpace(c); c != "" && r.Fields[c] == "" && (c != "impacto_seguridad" || !high) {
				missing = append(missing, catalog.Raw(c))
			}
		}
		if high && r.Impact == "" {
			missing = append(missing, catalog.Raw("impacto_seguridad"))
		}
		if prefix != "" && !strings.HasPrefix(r.ID, prefix) {
			missing = append(missing, catalog.Says("opexp5.prefix", "prefix", prefix))
		}
		if len(missing) > 0 {
			gaps = append(gaps, catalog.Says("item.name_list", "name", r.ID, "list", missing))
		}
	}

	if len(gaps) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.incomplete_requests", "list", gaps))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.complete_requests", "count", checked))
}

func JudgeEV04(requests []Request, machine string, accounts []string, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	var bad []string
	checked := 0
	for _, r := range requests {
		if !r.For(machine) || r.Risk != "alto" || (r.Status != "implantada" && r.Status != "revertida") || !r.Touches(now.Add(-RegisterHorizon)) {
			continue
		}
		checked++
		switch {
		case !slices.Contains(accounts, r.ApprovedBy):
			bad = append(bad, r.ID+" ("+r.ApprovedBy+")")
		case r.Approved.IsZero() || r.Approved.After(r.From):
			bad = append(bad, r.ID+" ("+r.Fields["fecha_aprobacion"]+")")
		}
	}

	if len(bad) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.high_risk_unapproved", "list", bad))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.high_risk_approved", "count", checked))
}

// Document is a row of P-06: a configuration document and the days it may take to follow a change.
type Document struct {
	Name string
	Days int
}

func JudgeEV06(requests []Request, machine string, documents []Document, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if len(documents) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_set", "param", "P-06"))
	}
	days := slices.MinFunc(documents, func(a, b Document) int { return a.Days - b.Days }).Days

	var undocumented []string
	checked := 0
	for _, r := range requests {
		end := r.Until
		if end.IsZero() {
			end = r.From
		}
		if !r.For(machine) || r.Status != "implantada" || end.IsZero() || now.Sub(end) < time.Duration(days)*24*time.Hour || now.Sub(end) > RegisterHorizon {
			continue
		}
		checked++
		if r.Documents == "" {
			undocumented = append(undocumented, r.ID)
		}
	}

	if len(undocumented) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.undocumented", "list", undocumented))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.documented", "count", checked))
}

// JudgeEV07 fails a service down now after a change in the hours before, unless the change was reverted.
func JudgeEV07(units *fact.UnitSnapshot, changes []Change, requests []Request, machine string, hours int, problem catalog.Message, now time.Time) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case units == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.UnitSnapshotFact))
	case units.Status == fact.SourceAbsent:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp5.no_systemd"))
	case units.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("systemctl", units.Status, units.Error))
	}
	if len(units.Failed) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.no_failed_services"))
	}

	var recent []Change
	for _, c := range changes {
		if now.Sub(c.Time) > time.Duration(hours)*time.Hour {
			continue
		}
		reverted := slices.ContainsFunc(requests, func(r Request) bool { return r.Covers(machine, c.Time) && r.Status == "revertida" })
		if !reverted {
			recent = append(recent, c)
		}
	}

	if len(recent) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.failed_after_change", "services", units.Failed, "changes", list(recent), "hours", hours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp5.failed_unrelated", "services", units.Failed, "hours", hours))
}

// JudgeEV09 needs a snapshot taken at most hours before every change.
func JudgeEV09(changes []Change, s *fact.SnapshotList, hours int, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case s == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.SnapshotListFact))
	case s.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("snapshots", s.Status, s.Error))
	}

	var taken []time.Time
	for _, sn := range s.Snapshots {
		if c, err := time.Parse(time.RFC3339, sn.Created); err == nil {
			taken = append(taken, c)
		}
	}

	var bare []Change
	for _, c := range changes {
		if !slices.ContainsFunc(taken, func(t time.Time) bool { return !t.After(c.Time) && c.Time.Sub(t) <= time.Duration(hours)*time.Hour }) {
			bare = append(bare, c)
		}
	}

	if len(bare) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.no_reversion_point", "list", list(bare), "hours", hours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.reversion_points", "count", len(changes), "hours", hours))
}

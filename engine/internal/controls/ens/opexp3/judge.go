// Package opexp3 judges op.exp.3, management of the security configuration: the op.exp.2 baseline held over
// time, who edits the security configuration, what is installed and runs, copies and verifications.
package opexp3

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc4"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// JudgeEV01 needs the lowest score of each assessed baseline policy in the series to reach the op.exp.2
// minimum. assessed is the op.exp.2 judgement of the same baseline: when it fails, so does the series.
func JudgeEV01(assessed verdict.Judgement, policies []string, lowest map[string]int, minScore int, days int, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if assessed.Status != verdict.Compliant {
		return assessed
	}

	var low, kept []string
	for _, p := range policies {
		score, ok := lowest[strings.TrimSpace(p)]
		if !ok {
			continue
		}
		item := fmt.Sprintf("%s %d %%", strings.TrimSpace(p), score)
		if score < minScore {
			low = append(low, item)
		} else {
			kept = append(kept, item)
		}
	}
	slices.Sort(low)
	slices.Sort(kept)

	if len(low) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.series_below", "policies", low, "min", minScore, "days", days))
	}
	// No summary in the series: the result has not changed in it, and the newest one (op.exp.2) holds.
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.series_kept", "policies", kept, "min", minScore, "days", days, "baseline", assessed.Message))
}

// Edits are the successful audited writes of the window under the security configuration paths.
func Edits(accesses []source.AuditAccess, paths []string) []source.AuditAccess {
	var out []source.AuditAccess
	for _, a := range accesses {
		if a.Key != "oscompliance_write" || a.Success != "yes" {
			continue
		}
		if slices.ContainsFunc(paths, func(p string) bool { return under(a.Path, p) }) {
			out = append(out, a)
		}
	}
	return out
}

func under(path, root string) bool {
	root = strings.TrimRight(strings.TrimSpace(root), "/")
	return root != "" && (path == root || strings.HasPrefix(path, root+"/"))
}

// editors are the accounts behind the edits, and the paths whose account cannot be named.
func editors(edits []source.AuditAccess, accounts opacc4.Accounts) (map[string][]string, []string) {
	who := map[string][]string{}
	var unnamed []string
	for _, a := range edits {
		if name := opacc4.Person(a, accounts); name == "" {
			unnamed = append(unnamed, a.Path)
		} else if !slices.Contains(who[name], a.Path) {
			who[name] = append(who[name], a.Path)
		}
	}
	return who, unnamed
}

func JudgeEV02(edits []source.AuditAccess, accounts opacc4.Accounts, authorised []string, problem, chain catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	who, unnamed := editors(edits, accounts)

	var others []catalog.Message
	for name, paths := range who {
		if !slices.ContainsFunc(authorised, func(a string) bool { return strings.TrimSpace(a) == name }) {
			slices.Sort(paths)
			others = append(others, catalog.Says("item.name_list", "name", name, "list", paths))
		}
	}
	catalog.SortMessages(others)

	switch {
	case len(others) > 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.edited_by_others", "list", others))
	case len(unnamed) > 0:
		slices.Sort(unnamed)
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opexp3.edits_unnamed", "paths", slices.Compact(unnamed)))
	case !chain.IsZero():
		return passes.Gap(verdict.CauseCollection, chain)
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.edits_authorised", "count", len(edits), "accounts", len(who)))
}

func JudgeEV08(edits []source.AuditAccess, accounts opacc4.Accounts, max int, problem, chain catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	who, unnamed := editors(edits, accounts)
	names := make([]string, 0, len(who))
	for n := range who {
		names = append(names, n)
	}
	slices.Sort(names)

	switch {
	case len(names) > max:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.too_many_admins", "count", len(names), "max", max, "accounts", names))
	case len(unnamed) > 0:
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opexp3.edits_unnamed", "paths", unnamed))
	case !chain.IsZero():
		return passes.Gap(verdict.CauseCollection, chain)
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.admins", "count", len(names), "max", max, "accounts", names))
}

// JudgeEV03 fails a package newly installed on request that P-01 does not authorise; dependencies pass.
func JudgeEV03(installed []string, selection *fact.PackageSelection, authorised []string, problem catalog.Message) verdict.Judgement {

	switch {
	case selection == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.PackageSelectionFact))
	case selection.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source(selection.Manager, selection.Status, selection.Error))
	case selection.Manager == "dnf":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp3.dnf_not_decoded"))
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	var unauthorised []string
	requested := 0
	for _, p := range installed {
		if !slices.Contains(selection.Packages, p) {
			continue
		}
		requested++
		if !slices.ContainsFunc(authorised, func(a string) bool { return strings.TrimSpace(a) == p }) {
			unauthorised = append(unauthorised, p)
		}
	}
	slices.Sort(unauthorised)

	if len(unauthorised) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.unauthorised_software", "list", unauthorised))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.software_authorised", "installed", len(installed), "requested", requested))
}

// JudgeEV04 needs every running unit, and every listening process outside a unit, in P-02. A template
// unit (`getty@.service`) covers its instances.
func JudgeEV04(units *fact.UnitSnapshot, listening *fact.ListeningSnapshot, sockets []fact.ListeningSocket, authorised []string, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case units == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.UnitSnapshotFact))
	case units.Status == fact.SourceError:
		return passes.Gap(verdict.CauseCollection, passes.Source("systemctl", units.Status, units.Error))
	case listening == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.ListeningSnapshotFact))
	case len(sockets) < listening.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, passes.Incomplete(listening.RunID, len(sockets), listening.RecordsEmitted, fact.ListeningSocketFact))
	}

	allowed := func(name string) bool {
		return slices.ContainsFunc(authorised, func(a string) bool {
			a = strings.TrimSpace(a)
			if a == name {
				return true
			}
			prefix, ok := strings.CutSuffix(a, "@.service")
			return ok && strings.HasPrefix(name, prefix+"@") && strings.HasSuffix(name, ".service")
		})
	}

	var extra []string
	running := units.Units
	for _, u := range running {
		if !allowed(u) {
			extra = append(extra, u)
		}
	}
	processes := 0
	for _, s := range sockets {
		if s.Unit != "" || s.Process == "" {
			continue
		}
		processes++
		if !allowed(s.Process) && !slices.Contains(extra, s.Process) {
			extra = append(extra, s.Process)
		}
	}
	slices.Sort(extra)

	if len(extra) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.unauthorised_services", "list", extra))
	}
	if units.Status == fact.SourceAbsent {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.processes_authorised", "count", processes))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.services_authorised", "units", len(running), "processes", processes))
}

// JudgeEV09 needs the newest copy of every source of P-07 within maxHours.
func JudgeEV09(b *fact.BackupSnapshot, sources []string, maxHours int, problem catalog.Message, now time.Time) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case len(sources) == 0:
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp3.no_backup_source"))
	case b == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.BackupSnapshotFact))
	case b.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("backup_sources", b.Status, b.Error))
	}

	read := map[string]fact.BackupSource{}
	for _, s := range b.Sources {
		read[s.Source] = s
	}

	var old, fresh []string
	for _, src := range sources {
		s, ok := read[src]
		switch {
		case !ok:
			return passes.Gap(verdict.CauseCollection, catalog.Says("opexp3.backup_not_read", "source", src))
		case s.Status == fact.SourceAbsent:
			old = append(old, src+" (-)")
			continue
		case s.Status != fact.SourceRead:
			return passes.Gap(verdict.CauseCollection, passes.Source(src, s.Status, s.Error))
		}
		t, err := time.Parse(time.RFC3339, s.Newest)
		if err != nil {
			return passes.Gap(verdict.CauseEvidence, catalog.Says("item.error", "path", src, "error", err.Error()))
		}
		item := fmt.Sprintf("%s (%s)", src, t.UTC().Format("2006-01-02 15:04"))
		if now.Sub(t) > time.Duration(maxHours)*time.Hour {
			old = append(old, item)
		} else {
			fresh = append(fresh, item)
		}
	}

	if len(old) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.backups_old", "list", old, "max", maxHours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.backups_fresh", "list", fresh, "max", maxHours))
}

// JudgeEV10 fails any check that went from passed to failed since cut.
func JudgeEV10(regressions []source.SCARegression, cut time.Time, days int) verdict.Judgement {

	var list []string
	for _, r := range regressions {
		if !r.Time.Before(cut) {
			list = append(list, fmt.Sprintf("%s %s %s", r.PolicyID, r.CheckID, r.Title))
		}
	}
	if len(list) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.no_regressions", "days", days))
	}
	slices.Sort(list)
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.regressions", "list", list, "days", days))
}

// JudgeEV05 needs every edit of the security configuration covered by an approved request of the change
// register (op.exp.5 P-10).
func JudgeEV05(fim []source.FIMChange, paths []string, requests []opexp5.Request, machine string, problem catalog.Message, since time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	var edits []source.FIMChange
	for _, f := range fim {
		if slices.ContainsFunc(paths, func(p string) bool { return under(f.Path, p) }) {
			edits = append(edits, f)
		}
	}
	changes := opexp5.Changes(edits, nil, since)
	if bare := opexp5.Uncovered(changes, requests, machine); len(bare) > 0 {
		list := make([]string, len(bare))
		for i, c := range bare {
			list[i] = c.String()
		}
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp3.edits_unauthorised", "list", list))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp3.edits_covered", "count", len(changes)))
}

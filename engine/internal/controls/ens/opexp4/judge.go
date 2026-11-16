package opexp4

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var severities = map[string]string{"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}

const unscored = "Sin puntuación"

func severityName(s string) string {
	if n, ok := severities[strings.ToLower(strings.TrimSpace(s))]; ok {
		return n
	}
	return unscored
}

func counts(days []source.VulnerabilityDay) []string {
	by := map[string]int{}
	for _, d := range days {
		by[severityName(d.Severity)] += d.Count
	}
	var out []string
	for _, name := range []string{"Crítica", "Alta", "Media", "Baja", unscored} {
		if by[name] > 0 {
			out = append(out, fmt.Sprintf("%s %d", name, by[name]))
		}
	}
	return out
}

func JudgeEV01(packages verdict.Judgement, manager bool, days []source.VulnerabilityDay) verdict.Judgement {

	if manager {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.manager_not_scanned"))
	}
	if packages.Status != verdict.Compliant {
		return packages
	}
	if len(days) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.no_vulnerabilities"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.vulnerabilities", "counts", counts(days)))
}

func Deadlines(rows []string) (map[string]int, catalog.Message) {
	out := map[string]int{}
	for _, r := range rows {
		name, days, _ := strings.Cut(r, "|")
		name, days = strings.TrimSpace(name), strings.TrimSpace(days)
		if days == "" {
			continue
		}
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return nil, catalog.Says("param.not_days", "param", "P-01", "value", days)
		}
		out[strings.ToLower(name)] = n
	}
	return out, catalog.Message{}
}

func JudgeEV02(manager bool, days []source.VulnerabilityDay, deadlines map[string]int, problem catalog.Message, now time.Time) verdict.Judgement {

	if manager {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.manager_not_scanned"))
	}
	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}

	overdue := map[string]int{}
	var examples []string
	within := 0
	for _, d := range days {
		name := severityName(d.Severity)
		limit, ok := deadlines[strings.ToLower(name)]
		if !ok {
			within += d.Count
			continue
		}
		if now.Sub(d.Detected) > time.Duration(limit)*24*time.Hour {
			overdue[name] += d.Count
			for _, e := range d.Examples {
				if len(examples) < 5 && !slices.Contains(examples, e) {
					examples = append(examples, e)
				}
			}
		} else {
			within += d.Count
		}
	}

	if len(overdue) > 0 {
		var list []string
		for _, name := range []string{"Crítica", "Alta", "Media", "Baja", unscored} {
			if overdue[name] > 0 {
				list = append(list, fmt.Sprintf("%s %d (%d días)", name, overdue[name], deadlines[strings.ToLower(name)]))
			}
		}
		slices.Sort(examples)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.overdue", "list", list, "examples", examples))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.within_deadline", "count", within))
}

func JudgeEV03(u *fact.UpdateStatus, maxDays int, problem catalog.Message, now time.Time) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case u == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.UpdateStatusFact))
	case u.Manager == "none":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.no_apt"))
	case u.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("apt-get -s dist-upgrade", u.Status, u.Error))
	}

	lists, err := time.Parse(time.RFC3339, u.ListsUpdated)
	if err != nil {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.no_lists"))
	}
	if age := int(now.Sub(lists).Hours() / 24); age > maxDays {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.lists_old", "days", age, "max", maxDays, "pending", u.Pending, "security", u.Security))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.updates", "pending", u.Pending, "security", u.Security, "since", lists.UTC().Format("2006-01-02")))
}

type Transactions struct {
	Snapshot *fact.TransactionSnapshot
	Records  []fact.PackageTransaction
}

func (t Transactions) gap() (verdict.Judgement, bool) {
	switch {
	case t.Snapshot == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.TransactionSnapshotFact)), true
	case t.Snapshot.Manager == "none":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp4.no_apt")), true
	case t.Snapshot.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("/var/log/apt/history.log", t.Snapshot.Status, t.Snapshot.Error)), true
	case len(t.Records) < t.Snapshot.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, passes.Incomplete(t.Snapshot.RunID, len(t.Records), t.Snapshot.RecordsEmitted, fact.PackageTransactionFact)), true
	}
	return verdict.Judgement{}, false
}

func (t Transactions) since(from time.Time) []fact.PackageTransaction {
	var out []fact.PackageTransaction
	for _, r := range t.Records {
		if start, err := time.Parse(time.RFC3339, r.Start); err == nil && !start.Before(from) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b fact.PackageTransaction) int { return strings.Compare(a.Start, b.Start) })
	return out
}

func describe(t fact.PackageTransaction) string {
	return fmt.Sprintf("%s %s (%s)", t.Start, t.Actor, t.Command)
}

func JudgeEV04(t Transactions, from time.Time, authorised []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if gap, found := t.gap(); found {
		return gap
	}

	window := t.since(from)
	var others []string
	for _, r := range window {
		if !slices.ContainsFunc(authorised, func(a string) bool {
			name, _, _ := strings.Cut(a, "|")
			return strings.TrimSpace(name) == r.Actor
		}) {
			others = append(others, describe(r))
		}
	}

	if len(others) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.unauthorised_maintenance", "list", others))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.maintenance_authorised", "count", len(window)))
}

func JudgeEV05(system *source.System, rows []string, problem catalog.Message, now time.Time) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case system == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_inventory", "kind", catalog.Says("opexp1.kind_system")))
	}

	product := strings.ToLower(system.OS)
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 3 {
			c = append(c, "")
		}
		name, version, eol := strings.ToLower(strings.TrimSpace(c[0])), strings.TrimSpace(c[1]), strings.TrimSpace(c[2])
		if name == "" || !strings.Contains(product, name) || !strings.HasPrefix(system.Version, version) {
			continue
		}
		end, err := time.Parse("2006-01-02", eol)
		if err != nil {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.eol_not_date", "value", eol))
		}
		if now.After(end) {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.out_of_support", "os", system.OS+" "+system.Version, "eol", eol))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.supported", "os", system.OS+" "+system.Version, "eol", eol))
	}
	return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.no_eol_row", "os", system.OS+" "+system.Version))
}

func JudgeEV06(vendors []string, sources []string, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case len(vendors) == 0:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp1.no_inventory", "kind", catalog.Says("opexp1.kind_packages")))
	}

	var followed []string
	for _, s := range sources {
		name, _, _ := strings.Cut(s, "|")
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			followed = append(followed, name)
		}
	}

	var blind []string
	for _, v := range vendors {
		if !slices.ContainsFunc(followed, func(f string) bool { return strings.Contains(strings.ToLower(v), f) }) {
			blind = append(blind, v)
		}
	}
	slices.Sort(blind)

	if len(blind) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.vendors_unfollowed", "list", blind))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.vendors_followed", "count", len(vendors)))
}

type Window struct {
	Day        int
	Start, End int
}

var weekdays = map[string]int{"dom": 0, "lun": 1, "mar": 2, "mie": 3, "mié": 3, "jue": 4, "vie": 5, "sab": 6, "sáb": 6, "*": -1}

func ParseWindows(spec string) ([]Window, error) {
	var out []Window
	for _, part := range strings.Split(spec, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("«%s»", strings.TrimSpace(part))
		}
		day, ok := weekdays[strings.ToLower(f[0])]
		from, to, found := strings.Cut(f[1], "-")
		a, errA := minutes(from)
		b, errB := minutes(to)
		if !ok || !found || errA != nil || errB != nil {
			return nil, fmt.Errorf("«%s»", strings.TrimSpace(part))
		}
		out = append(out, Window{Day: day, Start: a, End: b})
	}
	return out, nil
}

func minutes(hhmm string) (int, error) {
	t, err := time.Parse("15:04", hhmm)
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}

func (w Window) Contains(t time.Time) bool {
	m := t.Hour()*60 + t.Minute()
	day := int(t.Weekday())
	if w.Start <= w.End {
		return (w.Day < 0 || w.Day == day) && m >= w.Start && m < w.End
	}
	previous := (day + 6) % 7
	return ((w.Day < 0 || w.Day == day) && m >= w.Start) || ((w.Day < 0 || w.Day == previous) && m < w.End)
}

func WindowsFor(rows []string, machine string) (string, bool) {
	general, found := "", false
	for _, r := range rows {
		name, spec, _ := strings.Cut(r, "|")
		name, spec = strings.TrimSpace(name), strings.TrimSpace(spec)
		if strings.EqualFold(name, machine) {
			return spec, true
		}
		if name == "*" {
			general, found = spec, true
		}
	}
	return general, found
}

func JudgeEV07(t Transactions, from time.Time, rows []string, machine string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	spec, ok := WindowsFor(rows, machine)
	if !ok {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.no_window", "machine", machine))
	}
	windows, err := ParseWindows(spec)
	if err != nil {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.window_invalid", "value", err.Error()))
	}
	if gap, found := t.gap(); found {
		return gap
	}

	window := t.since(from)
	var outside []string
	for _, r := range window {
		start, _ := time.Parse(time.RFC3339, r.Start)
		if !slices.ContainsFunc(windows, func(w Window) bool { return w.Contains(start) }) {
			outside = append(outside, describe(r))
		}
	}

	if len(outside) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.outside_windows", "list", outside, "windows", spec))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.inside_windows", "count", len(window), "windows", spec))
}

func JudgeEV08(machine string, rows []string, problem catalog.Message, installed map[string]time.Time, preprodInstalled map[string]time.Time, preprodNow map[string]bool, from time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	preprod := PreproductionOf(rows, machine)
	if preprod == "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp4.no_preproduction", "machine", machine))
	}

	var untested []string
	checked := 0
	for version, at := range installed {
		if at.Before(from) {
			continue
		}
		checked++
		if before, ok := preprodInstalled[version]; (ok && !before.After(at)) || preprodNow[version] {
			continue
		}
		untested = append(untested, version)
	}
	slices.Sort(untested)

	if len(untested) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.untested", "list", untested, "preprod", preprod))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.tested", "count", checked, "preprod", preprod))
}

func PreproductionOf(rows []string, machine string) string {
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) >= 2 && strings.EqualFold(strings.TrimSpace(c[0]), machine) {
			return strings.TrimSpace(c[1])
		}
	}
	return ""
}

func JudgeEV09(t Transactions, from time.Time, s *fact.SnapshotList, hours int, problem catalog.Message) verdict.Judgement {

	switch {
	case !problem.IsZero():
		return passes.Gap(verdict.CauseConfiguration, problem)
	case s == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.SnapshotListFact))
	case s.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("snapshots", s.Status, s.Error))
	}
	if gap, found := t.gap(); found {
		return gap
	}

	var taken []time.Time
	for _, sn := range s.Snapshots {
		if c, err := time.Parse(time.RFC3339, sn.Created); err == nil {
			taken = append(taken, c)
		}
	}

	window := t.since(from)
	var bare []string
	for _, r := range window {
		start, _ := time.Parse(time.RFC3339, r.Start)
		if !slices.ContainsFunc(taken, func(c time.Time) bool {
			return !c.After(start) && start.Sub(c) <= time.Duration(hours)*time.Hour
		}) {
			bare = append(bare, describe(r))
		}
	}

	if len(bare) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp4.no_reversion_point", "list", bare, "hours", hours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp4.reversion_points", "count", len(window), "hours", hours))
}

func ReversionHours(rows []string, machine string) (int, bool) {
	general, found := 0, false
	for _, r := range rows {
		c := strings.Split(r, "|")
		for len(c) < 4 {
			c = append(c, "")
		}
		h, err := strconv.Atoi(strings.TrimSpace(c[3]))
		if err != nil {
			continue
		}
		switch name := strings.TrimSpace(c[0]); {
		case strings.EqualFold(name, machine):
			return h, true
		case name == "*":
			general, found = h, true
		}
	}
	return general, found
}

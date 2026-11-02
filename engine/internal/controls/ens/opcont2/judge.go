package opcont2

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func Cells(row string, n int) []string {
	c := strings.Split(row, "|")
	for len(c) < n {
		c = append(c, "")
	}
	for i := range c {
		c[i] = strings.TrimSpace(c[i])
	}
	return c
}

func Date(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func Person(v string) string {
	v = strings.NewReplacer("á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u", "ü", "u", "ñ", "n").Replace(strings.ToLower(v))
	return strings.Join(strings.Fields(v), " ")
}

func JudgeEV01(rows []string, months int, now time.Time) verdict.Judgement {

	var newest time.Time
	var plan string
	for _, r := range rows {
		c := Cells(r, 3)
		if t, ok := Date(c[2]); ok && !t.After(now) && t.After(newest) {
			newest, plan = t, strings.TrimSpace(c[0]+" "+c[1])
		}
	}
	switch {
	case newest.IsZero():
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.no_approval"))
	case newest.AddDate(0, months, 0).Before(now):
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.plan_outdated", "plan", plan, "date", newest.Format("2006-01-02"), "months", months))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont2.plan_current", "plan", plan, "date", newest.Format("2006-01-02"), "months", months))
}

func JudgeEV04(rows []string, now time.Time) verdict.Judgement {

	var lacking, valid []catalog.Message
	for _, r := range rows {
		c := Cells(r, 5)
		until, ok := Date(c[3])
		switch {
		case c[2] == "":
			lacking = append(lacking, catalog.Says("opcont2.item_no_contract", "name", c[0]))
		case !ok || until.Before(now):
			lacking = append(lacking, catalog.Says("opcont2.item_expired", "name", c[0], "contract", c[2], "until", c[3]))
		default:
			valid = append(valid, catalog.Says("opcont2.item_contract", "name", c[0], "contract", c[2], "until", c[3]))
		}
	}
	if len(lacking) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.means_uncovered", "list", lacking))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont2.means_covered", "list", valid))
}

func JudgeEV06(functions, training []string, now time.Time) verdict.Judgement {

	valid := map[string]bool{}
	for _, r := range training {
		c := Cells(r, 4)
		if until, ok := Date(c[3]); ok && !until.Before(now) {
			valid[Person(c[0])] = true
		}
	}

	var people, untrained []string
	for _, r := range functions {
		c := Cells(r, 3)
		for _, p := range c[1:3] {
			if p != "" && !slices.Contains(people, Person(p)) {
				people = append(people, Person(p))
				if !valid[Person(p)] {
					untrained = append(untrained, p)
				}
			}
		}
	}
	if len(untrained) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.untrained", "list", untrained))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont2.trained", "count", len(people)))
}

func JudgeEV03(config *fact.WazuhAgentConfig, paths []string) verdict.Judgement {

	switch {
	case config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact))
	case config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", config.Status, config.Error))
	case config.SyscheckDisabled || !config.SyscheckScanOnStart:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.no_scan_on_start"))
	}

	var unwatched []string
	for _, p := range paths {
		if !slices.ContainsFunc(config.Directories, func(d fact.FIMDirectory) bool {
			return p == d.Path || strings.HasPrefix(p, strings.TrimSuffix(d.Path, "/")+"/")
		}) {
			unwatched = append(unwatched, p)
		}
	}
	if len(unwatched) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opcont2.paths_unwatched", "list", unwatched))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opcont2.paths_checked", "count", len(paths)))
}

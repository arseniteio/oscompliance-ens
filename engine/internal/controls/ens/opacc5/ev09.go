package opacc5

import (
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

const deliveryLag = 10 * time.Minute

type LogPass struct {
	Snapshot fact.ServiceLogSnapshot
	Logs     []fact.ServiceLog
}

type EV09Input struct {
	Services []Service

	Passes []LogPass
}

func JudgeEV09(in EV09Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}

	var gaps []catalog.Message

	for _, s := range in.Services {

		if s.Declared && s.Log == nil {
			gaps = append(gaps, catalog.Says("opacc5.declared_not_collected", "service", s.Name))
			continue
		}

		if s.Log != nil && s.Log.Status == fact.SourceRead && s.Log.Size > 0 {
			if modified, err := time.Parse(time.RFC3339, s.Log.Modified); err == nil {
				if s.Span.Count == 0 || modified.Sub(s.Span.Newest) > deliveryLag {
					gaps = append(gaps, catalog.Says("opacc5.log_behind", "service", s.Name, "modified", s.Log.Modified, "newest", newest(s.Span.Newest, s.Span.Count)))
				}
			}
		}
	}

	for i := 1; i < len(in.Passes); i++ {
		gaps = append(gaps, compare(in.Passes[i-1], in.Passes[i])...)
	}

	if len(gaps) > 0 {
		catalog.SortMessages(gaps)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", gaps))
	}

	if len(in.Passes) < 2 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.continuity_needs_two_reads_of_the_logs_i"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_reads_of_the_logs_no_file_lost_truncat", "a", len(in.Passes)))
}

func newest(t time.Time, count int) string {
	if count == 0 {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func compare(before, after LogPass) []catalog.Message {

	now := map[string]fact.ServiceLog{}
	for _, l := range after.Logs {
		now[l.Service+"\x00"+l.Path] = l
	}

	var gaps []catalog.Message
	when := after.Snapshot.TS

	for _, prev := range before.Logs {

		if prev.Status != fact.SourceRead {
			continue
		}

		cur, ok := now[prev.Service+"\x00"+prev.Path]

		switch {
		case !ok:

		case cur.Status == fact.SourceAbsent:
			gaps = append(gaps, catalog.Says("opacc5.log_disappeared", "service", prev.Service, "path", prev.Path, "when", when))
		case cur.Status != fact.SourceRead:
		case cur.Inode != prev.Inode && !keptAside(cur, prev.Inode, before.Snapshot.TS):
			gaps = append(gaps, catalog.Says("opacc5.log_replaced", "service", prev.Service, "path", prev.Path, "when", when))
		case cur.Inode == prev.Inode && cur.Size < prev.Size:
			gaps = append(gaps, catalog.Says("opacc5.log_truncated", "service", prev.Service, "path", prev.Path, "when", when, "before", prev.Size, "after", cur.Size))
		}
	}

	return gaps
}

func keptAside(cur fact.ServiceLog, inode uint64, since string) bool {
	for _, r := range cur.Rotated {
		if r.Inode == inode || (strings.HasSuffix(r.Path, ".gz") && r.Modified >= since) {
			return true
		}
	}
	return false
}

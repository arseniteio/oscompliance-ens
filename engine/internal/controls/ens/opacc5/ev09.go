package opacc5

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
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

	var gaps []string

	for _, s := range in.Services {

		if s.Declared && s.Log == nil {
			gaps = append(gaps, s.Name+": declared in P-02 but no labelled localfile reaches the agent")
			continue
		}

		if s.Log != nil && s.Log.Status == fact.SourceRead && s.Log.Size > 0 {
			if modified, err := time.Parse(time.RFC3339, s.Log.Modified); err == nil {
				if s.Span.Count == 0 || modified.Sub(s.Span.Newest) > deliveryLag {
					gaps = append(gaps, fmt.Sprintf("%s: written at %s, newest event in Wazuh %s", s.Name, s.Log.Modified, newest(s.Span.Newest, s.Span.Count)))
				}
			}
		}
	}

	for i := 1; i < len(in.Passes); i++ {
		gaps = append(gaps, compare(in.Passes[i-1], in.Passes[i])...)
	}

	if len(gaps) > 0 {
		sort.Strings(gaps)
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(gaps, "; ")}
	}

	if len(in.Passes) < 2 {
		return passes.NotEvaluable(verdict.CauseCollection, "continuity needs two reads of the logs in the window")
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d reads of the logs, no file lost, truncated or rotated without a trace", len(in.Passes))}
}

func newest(t time.Time, count int) string {
	if count == 0 {
		return "none"
	}
	return t.UTC().Format(time.RFC3339)
}

func compare(before, after LogPass) []string {

	now := map[string]fact.ServiceLog{}
	for _, l := range after.Logs {
		now[l.Service+"\x00"+l.Path] = l
	}

	var gaps []string
	when := after.Snapshot.TS

	for _, prev := range before.Logs {

		if prev.Status != fact.SourceRead {
			continue
		}

		cur, ok := now[prev.Service+"\x00"+prev.Path]

		switch {
		case !ok:

		case cur.Status == fact.SourceAbsent:
			gaps = append(gaps, fmt.Sprintf("%s: %s disappeared by %s", prev.Service, prev.Path, when))
		case cur.Status != fact.SourceRead:
		case cur.Inode != prev.Inode && !keptAside(cur, prev.Inode, before.Snapshot.TS):
			gaps = append(gaps, fmt.Sprintf("%s: %s replaced by %s without a rotated copy", prev.Service, prev.Path, when))
		case cur.Inode == prev.Inode && cur.Size < prev.Size:
			gaps = append(gaps, fmt.Sprintf("%s: %s truncated by %s (%d to %d bytes)", prev.Service, prev.Path, when, prev.Size, cur.Size))
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

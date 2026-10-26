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

// deliveryLag is how long a written line may take to become an event.
const deliveryLag = 10 * time.Minute

// LogPass is one read of the service logs by the agent.
type LogPass struct {
	Snapshot fact.ServiceLogSnapshot
	Logs     []fact.ServiceLog
}

// EV09Input is what EV-09 (continuity of the access log) needs.
type EV09Input struct {
	Services []Service
	// Passes of the window, oldest first, complete ones only.
	Passes []LogPass
}

// JudgeEV09 judges EV-09 as described in catalog/docs/contracts/op.acc.5.md,
// for each declared service, comparing each pass with the one before:
//
//  1. No service: NOT_EVALUABLE, CONFIGURATION.
//  2. Gaps: the log disappeared; it was replaced (another inode) and no
//     rotated copy keeps the old one; it shrank without rotating; it was
//     written after the newest event Wazuh has of it (lines that never
//     arrived); or a declared service the agent does not read.
//  3. A gap: NON_COMPLIANT. Fewer than two passes: NOT_EVALUABLE,
//     COLLECTION. Otherwise COMPLIANT.
func JudgeEV09(in EV09Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}

	var gaps []string

	for _, s := range in.Services {

		// 2. Declared but not read: nothing of it reaches Wazuh.
		if s.Declared && s.Log == nil {
			gaps = append(gaps, s.Name+": declared in P-02 but no labelled localfile reaches the agent")
			continue
		}

		// Written but not indexed.
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

// compare finds the gaps between two reads of the same logs.
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
			// No longer declared: not a gap of the log.
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

// keptAside: a rotated copy holds the old inode, or a compressed copy was
// written since the previous read (compressing writes a new inode).
func keptAside(cur fact.ServiceLog, inode uint64, since string) bool {
	for _, r := range cur.Rotated {
		if r.Inode == inode || (strings.HasSuffix(r.Path, ".gz") && r.Modified >= since) {
			return true
		}
	}
	return false
}

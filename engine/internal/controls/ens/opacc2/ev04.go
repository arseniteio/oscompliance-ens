package opacc2

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type ACLs struct {
	Snapshot *fact.ACLSnapshot
	Records  []fact.ACLRecord
}

type EV04Input struct {
	ACLs ACLs

	Rows        []string
	RowsProblem string
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if in.RowsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-08: "+in.RowsProblem)
	}

	s := in.ACLs.Snapshot
	switch {
	case s == nil:
		return passes.NotEvaluable(verdict.CauseCollection, "no acl_snapshot in the window")
	case s.Status == fact.SourceAbsent:
		return passes.NotEvaluable(verdict.CauseCollection, "the group configuration carries no P-08 paths for this machine")
	case s.Status != fact.SourceRead:
		return passes.NotEvaluable(verdict.CauseCollection, s.Config+" unreadable: "+s.Error)
	case len(in.ACLs.Records) < s.RecordsEmitted:
		return passes.NotEvaluable(verdict.CauseCollection, fmt.Sprintf("ACL read %s incomplete: %d of %d acl_record received", s.RunID, len(in.ACLs.Records), s.RecordsEmitted))
	}

	byPath := map[string]fact.ACLRecord{}
	for _, r := range in.ACLs.Records {
		byPath[r.Path] = r
	}

	var deviations, gaps []string
	verified := 0

	for _, row := range in.Rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		for len(cells) < 4 {
			cells = append(cells, "")
		}
		path, mode, owner, acl := cells[0], cells[1], cells[2], cells[3]

		r, ok := byPath[path]

		switch {
		case !ok:
			gaps = append(gaps, path+": not in the paths the agent was sent")
			continue
		case r.Status == fact.SourceAbsent:
			gaps = append(gaps, path+": does not exist")
			continue
		case r.Status != fact.SourceRead:
			gaps = append(gaps, path+": "+r.Error)
			continue
		}

		var why []string

		if want, err := strconv.ParseUint(mode, 8, 32); err != nil {
			gaps = append(gaps, fmt.Sprintf("%s: declared mode %q is not octal", path, mode))
			continue
		} else if got, _ := strconv.ParseUint(r.Mode, 8, 32); got != want {
			why = append(why, fmt.Sprintf("mode %s, declared %s", r.Mode, mode))
		}

		if owner != "" && owner != r.Owner {
			why = append(why, fmt.Sprintf("owner %s, declared %s", r.Owner, owner))
		}

		if diff := aclDifference(acl, r.ACL); diff != "" {
			why = append(why, diff)
		}

		verified++
		if len(why) > 0 {
			deviations = append(deviations, path+": "+strings.Join(why, ", "))
		}
	}

	if len(deviations) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "rights differ from P-08: " + strings.Join(deviations, "; ")}
	}
	if len(gaps) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(gaps, "; "))
	}

	return verdict.Judgement{Status: verdict.Compliant, Reason: fmt.Sprintf("%d resources with the rights P-08 declares", verified)}
}

func aclDifference(declared string, applied []string) string {

	want := map[string]bool{}
	for _, e := range strings.FieldsFunc(declared, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		want[normalizeACL(e)] = true
	}

	var missing, extra []string

	for e := range want {
		if !slices.Contains(applied, e) {
			missing = append(missing, e)
		}
	}

	for _, e := range applied {
		if named(e) && !want[e] {
			extra = append(extra, e)
		}
	}

	slices.Sort(missing)
	slices.Sort(extra)

	var out []string
	if len(missing) > 0 {
		out = append(out, "ACL lacks "+strings.Join(missing, " "))
	}
	if len(extra) > 0 {
		out = append(out, "ACL has undeclared "+strings.Join(extra, " "))
	}
	return strings.Join(out, ", ")
}

func normalizeACL(e string) string {

	parts := strings.Split(strings.TrimSpace(e), ":")
	short := map[string]string{"user": "u", "group": "g", "mask": "m", "other": "o", "default": "d"}

	for i := range parts {
		if s, ok := short[parts[i]]; ok && i < len(parts)-1 {
			parts[i] = s
		}
	}

	last := parts[len(parts)-1]
	if len(last) < 3 && strings.Trim(last, "rwx-") == "" {
		perm := []byte("---")
		for _, c := range last {
			switch c {
			case 'r':
				perm[0] = 'r'
			case 'w':
				perm[1] = 'w'
			case 'x':
				perm[2] = 'x'
			}
		}
		parts[len(parts)-1] = string(perm)
	}

	return strings.Join(parts, ":")
}

func named(e string) bool {
	e = strings.TrimPrefix(e, "d:")
	return (strings.HasPrefix(e, "u:") || strings.HasPrefix(e, "g:")) && !strings.HasPrefix(e, "u::") && !strings.HasPrefix(e, "g::")
}

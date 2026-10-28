package opacc2

import (
	"slices"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
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
	RowsProblem catalog.Message
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if !in.RowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.RowsProblem)
	}

	s := in.ACLs.Snapshot
	switch {
	case s == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_acl_snapshot_in_the_window"))
	case s.Status == fact.SourceAbsent:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.the_group_configuration_carries_no_p_08"))
	case s.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.a_unreadable_b", "a", s.Config, "b", s.Error))
	case len(in.ACLs.Records) < s.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.acl_read_a_incomplete_b_of_c_acl_record", "a", s.RunID, "b", len(in.ACLs.Records), "c", s.RecordsEmitted))
	}

	byPath := map[string]fact.ACLRecord{}
	for _, r := range in.ACLs.Records {
		byPath[r.Path] = r
	}

	var deviations, gaps []catalog.Message
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
			gaps = append(gaps, catalog.Says("opacc2.acl_not_sent", "path", path))
			continue
		case r.Status == fact.SourceAbsent:
			gaps = append(gaps, catalog.Says("item.absent", "path", path))
			continue
		case r.Status != fact.SourceRead:
			gaps = append(gaps, catalog.Says("item.error", "path", path, "error", r.Error))
			continue
		}

		var why []catalog.Message

		if want, err := strconv.ParseUint(mode, 8, 32); err != nil {
			gaps = append(gaps, catalog.Says("opacc2.mode_not_octal", "path", path, "mode", mode))
			continue
		} else if got, _ := strconv.ParseUint(r.Mode, 8, 32); got != want {
			why = append(why, catalog.Says("opacc2.mode_differs", "got", r.Mode, "want", mode))
		}

		if owner != "" && owner != r.Owner {
			why = append(why, catalog.Says("opacc2.owner_differs", "got", r.Owner, "want", owner))
		}

		why = append(why, aclDifference(acl, r.ACL)...)

		verified++
		if len(why) > 0 {
			deviations = append(deviations, catalog.Says("item.path_list", "path", path, "list", why))
		}
	}

	if len(deviations) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.rights_differ_from_p_08_a", "a", deviations))
	}
	if len(gaps) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings", "list", gaps))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_resources_with_the_rights_p_08_declare", "a", verified))
}

func aclDifference(declared string, applied []string) []catalog.Message {

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

	var out []catalog.Message
	if len(missing) > 0 {
		out = append(out, catalog.Says("opacc2.acl_lacks", "entries", missing))
	}
	if len(extra) > 0 {
		out = append(out, catalog.Says("opacc2.acl_extra", "entries", extra))
	}
	return out
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

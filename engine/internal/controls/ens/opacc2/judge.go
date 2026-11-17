package opacc2

import (
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type Sweep struct {
	Snapshot *fact.FileSweepSnapshot
	Files    []fact.SpecialFile
}

type EV01Input struct {
	Sweep Sweep
	Umask *fact.UmaskSnapshot

	Scope         []string
	Exceptions    []string
	StickyAllowed bool
	MinUmask      string

	ConfigProblem catalog.Message
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ConfigProblem)
	}

	minimum, err := strconv.ParseUint(in.MinUmask, 8, 32)
	if err != nil || len(in.MinUmask) > 4 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.p_07_a_is_not_an_octal_umask", "a", in.MinUmask))
	}

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}
	if in.Umask == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_umask_snapshot_in_the_window"))
	}

	exception := map[string]bool{}
	for _, p := range in.Exceptions {
		exception[filepath.Clean(p)] = true
	}

	var writable []catalog.Message

	for _, f := range in.Sweep.Files {

		if !f.WorldWritable || !underAny(f.Path, in.Scope) || exception[f.Path] {
			continue
		}

		if in.StickyAllowed && f.Kind == "directory" && f.Sticky {
			continue
		}

		writable = append(writable, catalog.Says("item.path_mode", "path", f.Path, "mode", f.Mode))
	}

	var weak, blind []catalog.Message
	declared := 0

	for _, src := range in.Umask.Sources {

		switch src.Status {
		case fact.SourceAbsent:
			continue
		case fact.SourceUnreadable:
			blind = append(blind, catalog.Says("item.unreadable", "path", src.Path))
			continue
		}

		for _, u := range src.Uninterpretable {
			blind = append(blind, catalog.Says("opacc2.umask_not_octal", "path", src.Path, "umask", u))
		}

		for _, u := range src.Umasks {
			declared++
			value, _ := strconv.ParseUint(u, 8, 32)
			if value&minimum != minimum {
				weak = append(weak, catalog.Says("opacc2.umask_of", "path", src.Path, "umask", u))
			}
		}
	}

	var findings []catalog.Message

	if len(writable) > 0 {
		catalog.SortMessages(writable)
		findings = append(findings, catalog.Says("opacc2.world_writable", "files", writable))
	}
	if len(weak) > 0 {
		findings = append(findings, catalog.Says("opacc2.weak_umask", "minimum", in.MinUmask, "sources", weak))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); !partial.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_world_writable_found_but_a", "a", partial))
	}
	if len(blind) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.umask_cannot_be_known_a", "a", blind))
	}
	if declared == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_source_declares_a_umask"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.no_world_writable_in_a_p_02_paths_b_umas", "a", len(in.Scope), "b", declared, "c", in.MinUmask))
}

func underAny(path string, dirs []string) bool {
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

type EV02Input struct {
	Config  *fact.WazuhAgentConfig
	Changes []source.FIMChange
	Window  time.Duration

	Critical        []string
	CriticalProblem catalog.Message
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if !in.CriticalProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.CriticalProblem)
	}

	var changed []catalog.Message
	for _, c := range in.Changes {
		for _, p := range in.Critical {
			if under(c.Path, p) {
				event := catalog.Says("fim." + c.Event)
				if len(c.Changed) > 0 {
					event = catalog.Says("opacc2.fim_event_fields", "event", event, "fields", c.Changed)
				}
				changed = append(changed, catalog.Says("opacc2.file_changed", "path", c.Path, "event", event, "at", c.Time.UTC().Format(time.RFC3339)))
				break
			}
		}
	}

	if len(changed) > 0 {
		catalog.SortMessages(changed)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.critical_files_changed_a", "a", changed))
	}

	switch {
	case in.Config == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_wazuh_agent_config_in_the_window_what"))
	case in.Config.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.wazuh_agent_configuration_a_b", "a", in.Config.Status, "b", in.Config.Error))
	case in.Config.SyscheckDisabled:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.wazuh_fim_is_disabled_on_this_machine"))
	}

	var unwatched []catalog.Message
	for _, p := range in.Critical {
		if why := notWatched(*in.Config, p, in.Window); !why.IsZero() {
			unwatched = append(unwatched, catalog.Says("item.path_why", "path", p, "why", why))
		}
	}

	if len(unwatched) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.critical_paths_fim_does_not_watch_in_tim", "a", unwatched))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_critical_paths_watched_by_wazuh_fim_no", "a", len(in.Critical)))
}

func notWatched(c fact.WazuhAgentConfig, path string, window time.Duration) catalog.Message {

	for _, i := range c.Ignored {
		if under(path, i) {
			return catalog.Says("opacc2.fim_ignored", "rule", i)
		}
	}

	for _, d := range c.Directories {
		if !under(path, d.Path) {
			continue
		}
		if d.Realtime || d.Whodata {
			return catalog.Message{}
		}
		if c.SyscheckFrequency == 0 || time.Duration(c.SyscheckFrequency)*time.Second <= window {
			return catalog.Message{}
		}
		return catalog.Says("opacc2.fim_slow", "seconds", c.SyscheckFrequency)
	}

	return catalog.Says("opacc2.fim_uncovered")
}

func under(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

type EV03Input struct {
	Accounts Accounts
	Sudoers  Sudoers

	Elevations []source.Elevation
	Log        passes.AuthLog

	Groups []string
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if gap, found := passes.IdentityGap(in.Accounts.Identity, in.Accounts.IdentityRecords); found {
		return gap
	}
	if gap, found := passes.GroupGap(in.Accounts.Groups, in.Accounts.GroupRecords); found {
		return gap
	}

	sudoers := in.Sudoers.Snapshot
	switch {
	case sudoers == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_sudoers_snapshot_in_the_window"))
	case sudoers.Status == "unreadable":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_unreadable"))
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_read_incomplete_a_of_b_sudo_gran", "a", len(in.Sudoers.Grants), "b", sudoers.RecordsEmitted))
	}

	idx := indexAccounts(in.Accounts)
	privileged, _ := privilegedAccounts(idx, in.Groups, in.Sudoers.Grants)

	local := map[string]bool{}
	for _, r := range in.Accounts.IdentityRecords {
		local[r.AccountName] = true
		if r.UID == 0 {
			privileged[r.AccountName] = append(privileged[r.AccountName], "UID 0")
		}
	}

	var escalations, undecided []catalog.Message
	denied, used := 0, 0

	for _, e := range in.Elevations {

		times := max(e.Count, 1)
		if e.Denied {
			denied += times
			continue
		}
		used += times

		_, toPrivileged := privileged[e.To]
		_, fromPrivileged := privileged[e.From]

		switch {
		case !toPrivileged && local[e.To]:

		case fromPrivileged:
		case !local[e.From]:
			undecided = append(undecided, catalog.Says("opacc2.elevation_not_local", "method", e.Method, "from", e.From, "to", e.To))
		case sudoers.BlindSpots > 0:
			undecided = append(undecided, catalog.Says("opacc2.elevation_unnamed_grants", "method", e.Method, "from", e.From, "to", e.To))
		default:
			at := e.Time.UTC().Format("2006-01-02T15:04:05Z")
			if e.Command != "" {
				escalations = append(escalations, catalog.Says("opacc2.escalation_command", "method", e.Method, "from", e.From, "to", e.To, "command", e.Command, "at", at))
			} else {
				escalations = append(escalations, catalog.Says("opacc2.escalation", "method", e.Method, "from", e.From, "to", e.To, "at", at))
			}
		}
	}

	if len(escalations) > 0 {
		catalog.SortMessages(escalations)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.privilege_escalations_by_unprivileged_ac", "a", escalations))
	}

	if len(undecided) > 0 {
		catalog.SortMessages(undecided)
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings", "list", undecided))
	}

	if used == 0 && denied == 0 && !in.Log.Reaches {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.elevations_cannot_be_seen_a", "a", in.Log.Detail))
	}

	if used == 0 && denied == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.no_sudo_or_su_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_elevations_by_privileged_accounts_or_t", "a", used, "b", denied))
}

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

	var deviations, gaps, missing []catalog.Message
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
			missing = append(missing, catalog.Raw(path))
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
	if len(missing) > 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.declared_missing", "paths", missing, "verified", verified))
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

type Accounts struct {
	Identity        *fact.IdentitySnapshot
	IdentityRecords []fact.IdentityRecord
	Groups          *fact.GroupSnapshot
	GroupRecords    []fact.GroupRecord
}

type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

type EV05Input struct {
	Accounts Accounts
	Sudoers  Sudoers

	Groups   []string
	Declared []string

	ConfigProblem catalog.Message
}

func JudgeEV05(in EV05Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if gap, found := passes.IdentityGap(in.Accounts.Identity, in.Accounts.IdentityRecords); found {
		return gap
	}
	if gap, found := passes.GroupGap(in.Accounts.Groups, in.Accounts.GroupRecords); found {
		return gap
	}

	sudoers := in.Sudoers.Snapshot

	switch {
	case sudoers == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.no_sudoers_snapshot_in_the_window"))
	case sudoers.Status == fact.SourceUnreadable:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_unreadable"))
	case len(in.Sudoers.Grants) < sudoers.RecordsEmitted:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_read_a_incomplete_b_of_c_sudo_gr", "a", sudoers.RunID, "b", len(in.Sudoers.Grants), "c", sudoers.RecordsEmitted))
	}

	privileged, unresolved := privilegedAccounts(indexAccounts(in.Accounts), in.Groups, in.Sudoers.Grants)

	declared := map[string]bool{}
	for _, name := range in.Declared {
		declared[name] = true
	}

	var undeclared []catalog.Message
	for name, via := range privileged {
		if !declared[name] {
			undeclared = append(undeclared, catalog.Says("item.name_list", "name", name, "list", via))
		}
	}

	if len(undeclared) > 0 {
		catalog.SortMessages(undeclared)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.privileges_not_declared_in_p_09_a", "a", undeclared))
	}

	if sudoers.BlindSpots > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_has_a_grants_not_attributable_to", "a", sudoers.BlindSpots, "b", strings.Join(sudoers.BlindSpotReasons, "; ")))
	}
	if len(unresolved) > 0 {
		sort.Strings(unresolved)
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.sudoers_names_groups_or_uids_that_do_not", "a", unresolved))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_privileged_accounts_all_declared_in_p", "a", len(privileged)))
}

type accountIndex struct {
	byUID      map[int]string
	groupGID   map[string]int
	groupByGID map[int]string
	secondary  map[string][]string
	primary    map[int][]string
}

func indexAccounts(a Accounts) accountIndex {

	idx := accountIndex{byUID: map[int]string{}, groupGID: map[string]int{}, groupByGID: map[int]string{}, secondary: map[string][]string{}, primary: map[int][]string{}}

	for _, r := range a.IdentityRecords {
		if _, seen := idx.byUID[r.UID]; !seen {
			idx.byUID[r.UID] = r.AccountName
		}
		idx.primary[r.GID] = append(idx.primary[r.GID], r.AccountName)
	}

	for _, g := range a.GroupRecords {
		if _, seen := idx.groupGID[g.GroupName]; seen {
			continue
		}
		idx.groupGID[g.GroupName] = g.GID
		if _, seen := idx.groupByGID[g.GID]; !seen {
			idx.groupByGID[g.GID] = g.GroupName
		}
		idx.secondary[g.GroupName] = g.Members
	}

	return idx
}

func (idx accountIndex) members(group string) []string {

	seen := map[string]bool{}
	var out []string

	for _, name := range idx.secondary[group] {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}

	if gid, ok := idx.groupGID[group]; ok {
		for _, name := range idx.primary[gid] {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}

	return out
}

var accessKinds = map[string]string{
	"oscompliance_read":  "lectura",
	"oscompliance_write": "escritura",
	"oscompliance_exec":  "ejecucion",
	"oscompliance_attr":  "modificacion",
}

type EV06Input struct {
	Watches  *fact.AuditWatchSnapshot
	Config   *fact.WazuhAgentConfig
	Accesses []source.AuditAccess
	Accounts Accounts

	Rules    []string
	Profiles []string
	Problem  catalog.Message
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.Problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.Problem)
	}

	type rule struct {
		profile, path string
		allowed       map[string]bool
	}
	var rules []rule
	var paths []string
	for _, r := range in.Rules {
		c := cellsOf(r, 3)
		allowed := map[string]bool{}
		for _, t := range strings.FieldsFunc(c[2], func(r rune) bool { return r == ',' || r == ' ' }) {
			allowed[strings.ToLower(t)] = true
		}
		rules = append(rules, rule{profile: c[0], path: c[1], allowed: allowed})
		paths = appendNew(paths, c[1])
	}

	profileOf := map[string]string{}
	for _, r := range in.Profiles {
		c := cellsOf(r, 2)
		if c[0] != "" {
			profileOf[c[0]] = c[1]
		}
	}

	byUID := map[int]string{}
	for _, r := range in.Accounts.IdentityRecords {
		if _, seen := byUID[r.UID]; !seen {
			byUID[r.UID] = r.AccountName
		}
	}

	var violations, blind []catalog.Message
	noProfile, judged := 0, 0

	for _, a := range in.Accesses {

		if a.Success != "yes" {
			continue
		}

		kind, ok := accessKinds[a.Key]
		if !ok {
			continue
		}

		who := person(a, byUID)
		if who == "" {
			blind = append(blind, catalog.Says("opacc2.access_no_person", "path", a.Path))
			continue
		}

		profile, declared := profileOf[who]
		if !declared {
			noProfile++
			continue
		}

		best := -1
		for i, r := range rules {
			if r.profile == profile && under(a.Path, r.path) && (best < 0 || len(r.path) > len(rules[best].path)) {
				best = i
			}
		}
		if best < 0 {
			blind = append(blind, catalog.Says("opacc2.access_no_rule", "path", a.Path, "account", who, "profile", profile))
			continue
		}

		judged++
		if !rules[best].allowed[kind] {
			violations = append(violations, catalog.Says("opacc2.access_violation", "kind", catalog.Says("access."+kind), "account", who, "profile", profile, "path", a.Path))
		}
	}

	if len(violations) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc2.accesses_beyond_the_permitted_type_a", "a", catalog.UniqueMessages(violations)))
	}

	if len(blind) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings", "list", catalog.UniqueMessages(blind)))
	}

	if gap := auditChain(in.Watches, in.Config, paths); !gap.IsZero() {
		return passes.Gap(verdict.CauseCollection, gap)
	}

	if noProfile > 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.accesses_permitted_unprofiled", "accesses", judged, "unprofiled", noProfile))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.accesses_permitted", "accesses", judged))
}

func person(a source.AuditAccess, byUID map[int]string) string {
	if a.Account != "" {
		return a.Account
	}
	for _, id := range []string{a.AUID, a.UID} {
		if id == "" || id == "unset" || id == "-1" || id == "4294967295" {
			continue
		}
		if n, err := strconv.Atoi(id); err == nil {
			if name, ok := byUID[n]; ok {
				return name
			}
			continue
		}
		return id
	}
	return ""
}

func auditChain(w *fact.AuditWatchSnapshot, c *fact.WazuhAgentConfig, paths []string) catalog.Message {

	switch {
	case w == nil:
		return catalog.Says("gap.no_fact", "fact", "audit_watch_snapshot")
	case w.Auditd != fact.AuditdRunning:
		return catalog.Says("chain.auditd", "state", catalog.Says("auditd."+w.Auditd), "error", w.Error)
	}

	for _, p := range paths {
		watched := false
		for _, l := range w.Loaded {
			if under(p, l) {
				watched = true
			}
		}
		if !watched {
			return catalog.Says("chain.unwatched", "path", p)
		}
	}

	if c == nil || c.Status != fact.SourceRead {
		return catalog.Says("chain.config_unknown")
	}
	for _, l := range c.Localfiles {
		if l.Format == "audit" {
			return catalog.Message{}
		}
	}
	return catalog.Says("chain.no_audit_log")
}

func cellsOf(row string, n int) []string {
	cells := strings.Split(row, "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	for len(cells) < n {
		cells = append(cells, "")
	}
	return cells
}

func appendNew(list []string, v string) []string {
	if contains(list, v) {
		return list
	}
	return append(list, v)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

type EV07Input struct {
	Sweep Sweep

	Authorized        []string
	AuthorizedProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if gap, found := passes.SweepGap(in.Sweep.Snapshot, in.Sweep.Files); found {
		return gap
	}

	authorized := map[string]bool{}
	for _, p := range in.Authorized {
		authorized[filepath.Clean(p)] = true
	}

	var unowned, unauthorized []catalog.Message
	privileged := 0

	for _, f := range in.Sweep.Files {

		if f.NoOwner || f.NoGroup {
			unowned = append(unowned, catalog.Says("opacc2.unowned_file", "path", f.Path, "uid", f.UID, "gid", f.GID))
		}

		if f.SUID || f.SGID {
			privileged++
			if in.AuthorizedProblem.IsZero() && !authorized[f.Path] {
				unauthorized = append(unauthorized, catalog.Says("item.path_mode", "path", f.Path, "mode", f.Mode))
			}
		}
	}

	var findings []catalog.Message

	if len(unowned) > 0 {
		catalog.SortMessages(unowned)
		findings = append(findings, catalog.Says("opacc2.without_owner", "files", unowned))
	}

	if len(unauthorized) > 0 {
		catalog.SortMessages(unauthorized)
		findings = append(findings, catalog.Says("opacc2.suid_not_in_p10", "files", unauthorized))
	}

	if len(findings) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings", "list", findings))
	}

	if privileged > 0 && !in.AuthorizedProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc2.a_suid_sgid_files_and_p_10_cannot_be_use", "a", privileged, "b", in.AuthorizedProblem))
	}

	if partial := passes.Partial(*in.Sweep.Snapshot); !partial.IsZero() {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc2.nothing_found_but_a", "a", partial))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc2.a_suid_sgid_files_all_in_p_10_no_file_wi", "a", privileged))
}

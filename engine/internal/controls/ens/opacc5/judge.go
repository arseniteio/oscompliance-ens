package opacc5

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type EV01Input struct {
	Services []Service
	Now      time.Time

	MinDays        int
	MinDaysProblem catalog.Message
}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if !in.MinDaysProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MinDaysProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var short, unknown, kept []catalog.Message

	for _, s := range in.Services {

		oldest := s.Span.Oldest
		if s.Span.Count == 0 {
			oldest = time.Time{}
		}
		if s.Log != nil && s.Log.EarliestEvent != "" {
			if t, err := time.Parse(time.RFC3339, s.Log.EarliestEvent); err == nil && (oldest.IsZero() || t.Before(oldest)) {
				oldest = t
			}
		}

		if oldest.IsZero() {
			unknown = append(unknown, catalog.Says("opacc5.no_log_age", "service", s.Name))
			continue
		}

		d := int(in.Now.Sub(oldest).Hours() / 24)
		item := catalog.Says("opacc5.log_age", "service", s.Name, "days", d, "since", oldest.UTC().Format("2006-01-02"))

		if d < in.MinDays {
			short = append(short, item)
		} else {
			kept = append(kept, item)
		}
	}

	if len(short) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.access_log_kept_less_than_a_days_b", "a", in.MinDays, "b", short))
	}
	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.access_log_kept_at_least_a_days_b", "a", in.MinDays, "b", kept))
}

func noService() verdict.Judgement {
	return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.no_external_user_service_on_this_machine"))
}

type EV02Input struct {
	Services []Service
	Policies map[string]Policy

	Events []source.ServiceEvent

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

func JudgeEV02(in EV02Input) verdict.Judgement {

	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	var failing, unknown, fine []catalog.Message

	for _, s := range in.Services {

		p := in.Policies[s.Name]

		switch {
		case !p.Found || p.Lockout == "":
			unknown = append(unknown, catalog.Says("opacc5.no_lockout_policy", "service", s.Name))
		case p.Lockout == "desactivado":
			failing = append(failing, catalog.Says("opacc5.lockout_disabled", "service", s.Name))
		case p.MaxAttempts == 0:
			unknown = append(unknown, catalog.Says("opacc5.lockout_no_attempts", "service", s.Name))
		case p.MaxAttempts > in.MaxAttempts:
			failing = append(failing, catalog.Says("opacc5.locks_late", "service", s.Name, "attempts", p.MaxAttempts, "max", in.MaxAttempts))
		case p.Reactivation == "automatica":
			failing = append(failing, catalog.Says("opacc5.auto_reactivation", "service", s.Name))
		default:
			fine = append(fine, catalog.Says("opacc5.locks_after", "service", s.Name, "attempts", p.MaxAttempts))
		}
	}

	failing = append(failing, longRuns(in.Events, in.MaxAttempts)...)

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.lockouts_fine", "list", fine, "max", in.MaxAttempts))
}

func longRuns(events []source.ServiceEvent, limit int) []catalog.Message {

	type state struct {
		run, longest int
		locked       bool
	}
	accounts := map[string]*state{}

	for _, e := range events {

		key := e.Service + " " + e.Usuario
		a, ok := accounts[key]
		if !ok {
			a = &state{}
			accounts[key] = a
		}

		switch {
		case e.Tipo == "bloqueo":
			a.run, a.locked = 0, true
		case e.Tipo == "desbloqueo":
			a.run, a.locked = 0, false
		case e.Tipo == "autenticacion" && e.Resultado == "exito":
			a.run, a.locked = 0, false
		case e.Tipo == "autenticacion" && e.Resultado == "fallo" && !a.locked:
			a.run++
			a.longest = max(a.longest, a.run)
		}
	}

	var out []catalog.Message
	for key, a := range accounts {
		if a.longest > limit {
			out = append(out, catalog.Says("opacc5.failures_in_a_row", "account", key, "count", a.longest))
		}
	}
	catalog.SortMessages(out)

	return out
}

const originSpan = 15 * time.Minute

type EV03Input struct {
	Services []Service

	Bursts   []source.Burst
	Failures []source.ServiceEvent

	Reaching map[string]bool

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	times := map[string][]time.Time{}
	for _, f := range in.Failures {
		key := f.Service + " " + origin(f.Origen)
		times[key] = append(times[key], f.Time)
	}

	var failing []catalog.Message
	failed := map[string]int{}

	for _, b := range in.Bursts {

		failed[b.Service] += b.Total
		if b.AtMost <= in.MaxAttempts {
			continue
		}

		key := b.Service + " " + origin(b.Key)
		if n := maxWithin(times[key], originSpan); n > in.MaxAttempts {
			failing = append(failing, catalog.Says("opacc5.failures_within", "origin", key, "count", n, "minutes", int(originSpan.Minutes())))
		}
	}

	if len(failing) > 0 {
		catalog.SortMessages(failing)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.origins_with_more_than_a_failures_b", "a", in.MaxAttempts, "b", failing))
	}

	var blind []string
	for _, s := range in.Services {
		if failed[s.Name] == 0 && !in.Reaching[s.Name] {
			blind = append(blind, s.Name)
		}
	}
	if len(blind) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.no_failure_seen_and_the_log_is_not_known", "a", blind))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.no_origin_failed_more_than_a_times_withi", "a", in.MaxAttempts, "b", int(originSpan.Minutes())))
}

func origin(o string) string {
	if o == "" {
		return "?"
	}
	return o
}

func maxWithin(times []time.Time, span time.Duration) int {

	sorted := append([]time.Time(nil), times...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })

	best, start := 0, 0
	for end := range sorted {
		for sorted[end].Sub(sorted[start]) > span {
			start++
		}
		best = max(best, end-start+1)
	}

	return best
}

type EV04Input struct {
	Services []Service
	Accounts []source.ServiceAccount
	Now      time.Time

	MaxAge        int
	MaxAgeProblem catalog.Message
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if !in.MaxAgeProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAgeProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	oldest := map[string]time.Time{}
	for _, s := range in.Services {
		if s.Span.Count > 0 {
			oldest[s.Name] = s.Span.Oldest
		}
	}

	limit := time.Duration(in.MaxAge) * 24 * time.Hour
	var old []catalog.Message
	var unknown []string
	active := 0

	for _, a := range in.Accounts {

		last := a.LastSuccess
		if a.LastChange.After(last) {
			last = a.LastChange
		}
		if last.IsZero() || (!a.LastDisabled.IsZero() && !a.LastDisabled.Before(last)) {
			continue
		}
		active++

		who := a.Service + " " + a.User

		switch {

		case !a.LastChange.IsZero():
			if age := in.Now.Sub(a.LastChange); age > limit {
				old = append(old, catalog.Says("opacc5.changed_days_ago", "account", who, "days", int(age.Hours()/24)))
			}

		case !oldest[a.Service].IsZero() && in.Now.Sub(oldest[a.Service]) > limit:
			old = append(old, catalog.Says("opacc5.no_change_in_index", "account", who, "days", int(in.Now.Sub(oldest[a.Service]).Hours()/24)))
		default:
			unknown = append(unknown, who)
		}
	}

	if len(old) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.credentials_older_than_a_days_b", "a", in.MaxAge, "b", old))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_credential_change_recorded_yet_for_a", "a", unknown))
	}
	if active == 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_account_of_the_services_logged_in_or"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_accounts_every_credential_changed_with", "a", active, "b", in.MaxAge))
}

type EV05Input struct {
	Services []Service

	Events []source.ServiceEvent
	Now    time.Time

	MaxHours        int
	MaxHoursProblem catalog.Message
}

func JudgeEV05(in EV05Input) verdict.Judgement {

	if !in.MaxHoursProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxHoursProblem)
	}
	if len(in.Services) == 0 {
		return noService()
	}

	type notice struct {
		at     time.Time
		reason string
		ref    string
	}
	open := map[string][]notice{}
	limit := time.Duration(in.MaxHours) * time.Hour

	var late, onTime []catalog.Message

	measure := func(who string, n notice, end time.Time, closed bool) {
		took := end.Sub(n.at)
		code := "opacc5.disabled_after"
		if !closed {
			code = "opacc5.still_enabled"
		}
		item := catalog.Says(code, "account", who, "reason", catalog.Says("opacc5.notice."+n.reason), "ref", n.ref, "hours", fmt.Sprintf("%.1f", took.Hours()))
		switch {
		case took > limit:
			late = append(late, item)
		case closed:
			onTime = append(onTime, item)
		}
	}

	for _, e := range in.Events {

		who := e.Service + " " + e.Usuario

		switch e.Tipo {
		case "notificacion_compromiso", "fin_relacion":
			ref := e.Referencia
			if ref == "" {
				ref = "-"
			}
			open[who] = append(open[who], notice{at: e.Time, reason: e.Tipo, ref: ref})
		case "inhabilitacion":
			for _, n := range open[who] {
				measure(who, n, e.Time, true)
			}
			delete(open, who)
		}
	}

	pending := 0
	for who, list := range open {
		for _, n := range list {
			pending++
			measure(who, n, in.Now, false)
		}
	}

	if len(late) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.not_disabled_within_a_hours_b", "a", in.MaxHours, "b", late))
	}

	if len(onTime) == 0 && pending == 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.the_services_logged_no_compromise_or_end"))
	}

	reason := catalog.Says("opacc5.disabled_within", "hours", in.MaxHours, "list", onTime)
	if pending > 0 {
		reason = catalog.Says("opacc5.disabled_within_pending", "reason", reason, "pending", pending)
	}
	return verdict.Explain(verdict.Compliant, "", reason)
}

var revealing = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"usuario_inexistente", regexp.MustCompile(`(?i)(usuario|cuenta|user|account)\s+(no\s+existe|inexistente|desconocid[oa]|no\s+encontrad[oa]|not\s+found|does\s+not\s+exist|unknown)|no\s+such\s+user|invalid\s+user(name)?\s*[.!]?\s*$`)},
	{"credencial_incorrecta", regexp.MustCompile(`(?i)^(la\s+)?(contrase[nñ]a|clave|password)\s+(es\s+)?(incorrecta|err[oó]nea|no\s+v[aá]lida|incorrect|wrong|invalid)`)},
	{"estado_de_cuenta", regexp.MustCompile(`(?i)(cuenta|usuario|account|user)\s+(est[aá]\s+)?(bloquead[oa]|caducad[oa]|expirad[oa]|deshabilitad[oa]|inhabilitad[oa]|suspendid[oa]|locked|expired|disabled|suspended)`)},
	{"traza_tecnica", regexp.MustCompile(`(?i)exception|traceback|stack\s*trace|SQLSTATE|ORA-\d+|nginx/\d|apache/\d|version\s+\d+\.\d+`)},
}

func RevealingPattern(message string) string {

	for _, r := range revealing {
		if r.re.MatchString(message) {
			return r.pattern
		}
	}
	return ""
}

type EV06Input struct {
	Services []Service

	Messages   []source.MessageCount
	EverLogged map[string]bool
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}

	var found []catalog.Message
	for _, m := range in.Messages {
		if p := RevealingPattern(m.Message); p != "" {
			msg := m.Message
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
			found = append(found, catalog.Says("opacc5.revealing", "service", m.Service, "pattern", p, "message", msg, "count", m.Count))
		}
	}

	if len(found) > 0 {
		catalog.SortMessages(found)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.rejections_that_reveal_why_a", "a", found))
	}

	var silent []string
	for _, s := range in.Services {
		if !in.EverLogged[s.Name] {
			silent = append(silent, s.Name)
		}
	}
	if len(silent) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_rejection_message_ever_logged_by_a", "a", silent))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_rejection_messages_of_the_window_revea", "a", len(in.Messages)))
}

func Reinforcement(factors []string) string {

	has := map[string]bool{}
	for _, f := range factors {
		has[strings.ToLower(strings.TrimSpace(f))] = true
	}
	second := has["pin"] || has["biometria"]

	switch {
	case has["tarjeta"] && second:
		return "R4"
	case has["certificado"] && second:
		return "R3"
	case has["password"] && has["otp"]:
		return "R2"
	case has["password"] && len(has) == 1:
		return "R1"
	}

	return ""
}

type EV07Input struct {
	Services []Service
	Methods  []source.MethodCount

	Mechanism string
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}
	if in.Mechanism == "" {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opacc5.p_01_not_usable_the_mechanism_to_compare"))
	}

	var other []catalog.Message
	unknown, total := 0, 0

	for _, m := range in.Methods {

		total += m.Count

		if m.Factors == "" {
			unknown += m.Count
			continue
		}

		if r := Reinforcement(strings.Split(m.Factors, "+")); r != in.Mechanism {
			class := catalog.Raw(r)
			if r == "" {
				class = catalog.Says("opacc5.no_mechanism")
			}
			other = append(other, catalog.Says("opacc5.login_method", "service", m.Service, "factors", m.Factors, "class", class, "count", m.Count))
		}
	}

	if len(other) > 0 {
		catalog.SortMessages(other)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.logins_not_by_a_b", "a", in.Mechanism, "b", other))
	}
	if unknown > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.a_successful_logins_without_factors_in_t", "a", unknown))
	}
	if total == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.no_successful_login_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_successful_logins_all_by_b", "a", total, "b", in.Mechanism))
}

type EV08Input struct {
	Services     []Service
	Certificates []source.CertificateCount

	Rows        []string
	RowsProblem catalog.Message
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}
	if !in.RowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.RowsProblem)
	}

	admitted := map[string]map[string]bool{}
	for _, r := range in.Rows {
		issuer, checks, _ := strings.Cut(r, "|")
		set := map[string]bool{}
		for _, c := range strings.FieldsFunc(strings.ToLower(checks), func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			set[c] = true
		}
		admitted[strings.TrimSpace(issuer)] = set
	}

	var failing []catalog.Message
	total := 0

	for _, c := range in.Certificates {

		total += c.Count
		issuer, revocation := c.Issuer, strings.ToLower(c.Revocation)

		checks, listed := admitted[issuer]

		switch {
		case !listed:
			failing = append(failing, catalog.Says("opacc5.issuer_not_admitted", "service", c.Service, "issuer", issuer, "count", c.Count))
		case !checks[revocation]:
			failing = append(failing, catalog.Says("opacc5.revocation_check", "service", c.Service, "issuer", issuer, "check", revocation, "demands", strings.Join(sortedKeys(checks), " | "), "count", c.Count))
		}
	}

	if len(failing) > 0 {
		catalog.SortMessages(failing)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}
	if total == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc5.no_certificate_login_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_certificate_logins_issuers_admitted_an", "a", total))
}

func sortedKeys(set map[string]bool) []string {
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

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

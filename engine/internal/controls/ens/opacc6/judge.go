package opacc6

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc1"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/history"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

type EV01Input struct {
	Settings Settings

	Log passes.AuthLog

	Sources        []string
	SourcesProblem catalog.Message
}

var quietLogLevels = map[string]bool{"QUIET": true, "FATAL": true, "ERROR": true}

func JudgeEV01(in EV01Input) verdict.Judgement {

	if !in.SourcesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.SourcesProblem)
	}

	local := false
	for _, s := range in.Sources {
		if strings.EqualFold(strings.TrimSpace(s), "local") {
			local = true
		}
	}
	if !local {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.p_03_lists_no_local_source_a_are_measure", "a", in.Sources))
	}

	var gaps []catalog.Message

	if in.Log.Known && !in.Log.Reaches {
		gaps = append(gaps, in.Log.Detail)
	}

	if gap, found := in.Settings.Gap(); found {
		if len(gaps) > 0 {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", gaps))
		}
		return gap
	}

	sshd := in.Settings.SSHD()

	switch sshd.Status {
	case fact.SourceAbsent:
	case fact.SourceRead:
		if level := strings.ToUpper(sshd.Get("loglevel")); quietLogLevels[level] {
			gaps = append(gaps, catalog.Says("opacc6.sshd_loglevel", "level", level))
		}
	default:
		if len(gaps) == 0 {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.sshd_t_not_read_a", "a", sshd.Error))
		}
	}

	if len(gaps) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", gaps))
	}

	if !in.Log.Known {
		return passes.Gap(verdict.CauseCollection, in.Log.Detail)
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.the_authentication_log_reaches_wazuh_a_a", "a", in.Log.Detail))
}

const (
	ReqR11 = "op.acc.6.r1.1"
	ReqR21 = "op.acc.6.r2.1"
	ReqR81 = "op.acc.6.r8.1"
)

var secondFactorModules = map[string]bool{
	"pam_google_authenticator.so": true, "pam_oath.so": true, "pam_u2f.so": true,
	"pam_duo.so": true, "pam_radius_auth.so": true, "pam_yubico.so": true, "pam_totp.so": true,
}

type EV02Input struct {
	Logins    []source.Login
	Listening Listening
	Settings  Settings
	PAM       PAM
	Log       passes.AuthLog

	Zones        Zones
	ZonesProblem catalog.Message
}

type access struct {
	what       catalog.Message
	controlled bool
	zoneKnown  bool
	factors    int
	password   bool
}

func JudgeEV02(in EV02Input) map[string]verdict.Judgement {

	out := map[string]verdict.Judgement{}

	gap, found := ev02Gap(in)

	for _, req := range []string{ReqR81, ReqR11, ReqR21} {
		if found {
			out[req] = gap
			continue
		}
		out[req] = judgeZone(req, in)
	}

	return out
}

func ev02Gap(in EV02Input) (verdict.Judgement, bool) {

	if !in.ZonesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ZonesProblem), true
	}
	if gap, found := in.Settings.Gap(); found {
		return gap, true
	}
	if gap, found := in.PAM.Gap(); found {
		return gap, true
	}
	if gap, found := in.Listening.Gap(); found {
		return gap, true
	}

	return verdict.Judgement{}, false
}

func judgeZone(req string, in EV02Input) verdict.Judgement {

	sshd := in.Settings.SSHD()
	match := in.Settings.HasMatch()

	needsTwo := func(a access) bool {
		switch req {
		case ReqR81:
			return !a.controlled
		case ReqR11:
			return !a.controlled && a.password
		}
		return true
	}

	var failing, unknown []catalog.Message

	for _, a := range accesses(in.Logins, in.Zones, sshd, in.PAM) {

		if !a.zoneKnown && req != ReqR21 {
			unknown = append(unknown, catalog.Says("opacc6.origin_not_address", "what", a.what))
			continue
		}
		if !needsTwo(a) {
			continue
		}

		switch {
		case a.factors == 0:
			unknown = append(unknown, catalog.Says("opacc6.factors_unknown", "what", a.what))
		case a.factors < 2 && match:
			unknown = append(unknown, catalog.Says("opacc6.one_factor_match", "what", a.what))
		case a.factors < 2:
			failing = append(failing, catalog.Says("opacc6.one_factor", "what", a.what))
		}
	}

	channels, _ := in.Listening.Channels()

	for _, c := range channels {

		if c.Kind != KindAuthentication {
			continue
		}

		minimum, password, known := channelFactors(c, sshd, in.PAM)

		var exposed []string
		for _, addr := range in.Listening.Exposed(c) {
			if controlled, _ := in.Zones.Controlled(addr); !controlled {
				exposed = append(exposed, addr)
			}
		}

		a := access{what: catalog.Says("opacc6.channel", "name", c.Name), controlled: len(exposed) == 0, zoneKnown: true, factors: minimum, password: password}
		if len(exposed) > 0 {
			a.what = catalog.Says("opacc6.channel_on", "name", c.Name, "addresses", exposed)
		}

		switch {
		case !needsTwo(a):
		case !known:
			unknown = append(unknown, catalog.Says("opacc6.channel_factors_unknown", "what", a.what))
		case minimum < 2 && match && c.Name == "ssh":
			unknown = append(unknown, catalog.Says("opacc6.accepts_one_factor_match", "what", a.what))
		case minimum < 2:
			failing = append(failing, catalog.Says("opacc6.accepts_one_factor", "what", a.what))
		}
	}

	if len(failing) > 0 {
		catalog.SortMessages(failing)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		catalog.SortMessages(unknown)
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	if len(in.Logins) == 0 && !in.Log.Reaches {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.logins_cannot_be_seen_a", "a", in.Log.Detail))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_logins_and_b_channels_examined_two_fac", "a", len(in.Logins), "b", len(channels), "c", req))
}

func accesses(logins []source.Login, zones Zones, sshd SSHD, pam PAM) []access {

	seen := map[string]bool{}
	var out []access

	for _, l := range logins {

		origin := l.SourceIP
		if l.Method != source.MethodSSHD {
			origin = "local"
		}

		key := strings.Join([]string{l.Account, origin, l.Method, l.Auth, l.KeyType}, "|")
		if seen[key] {
			continue
		}
		seen[key] = true

		a := access{what: catalog.Says("opacc6.login_of", "method", l.Method, "account", l.Account, "origin", origin)}
		a.controlled, a.zoneKnown = zones.Controlled(origin)

		switch l.Method {
		case source.MethodSSHD:
			a.factors, a.password = sshdLoginFactors(l, sshd, pam)
		case source.MethodSU:

			continue
		default:
			a.factors, a.password = 1, true
			if hasSecondFactor(pam, "login") {
				a.factors = 2
			}
		}

		out = append(out, a)
	}

	return out
}

func sshdLoginFactors(l source.Login, sshd SSHD, pam PAM) (factors int, password bool) {

	switch {
	case l.Auth == "publickey":
		factors = 1
		if strings.HasSuffix(strings.ToUpper(l.KeyType), "-SK") && strings.Contains(sshd.Get("pubkeyauthoptions"), "verify-required") {
			factors = 2
		}
	case l.Auth == "password":
		factors, password = 1, true
	case strings.HasPrefix(l.Auth, "keyboard-interactive"):
		factors, password = 1, true
		if hasSecondFactor(pam, "sshd") {
			factors = 2
		}
	case l.Auth == "":
		return 0, false
	default:
		factors = 1
	}

	if required := authenticationMethods(sshd, pam); required > factors {
		factors = required
	}

	return factors, password
}

func channelFactors(c Channel, sshd SSHD, pam PAM) (minimum int, password, known bool) {

	switch c.Name {
	case "ssh":
		if sshd.Status != fact.SourceRead {
			return 0, false, false
		}
		password = sshd.Get("passwordauthentication") == "yes" || sshd.Get("kbdinteractiveauthentication") == "yes"
		if required := authenticationMethods(sshd, pam); required > 0 {
			return required, password, true
		}
		minimum = 2
		for _, m := range enabledMethods(sshd, pam) {
			minimum = min(minimum, m)
		}
		return minimum, password, true
	case "ldap", "ldaps", "telnet", "ftp", "vnc":
		return 1, true, true
	}

	return 0, true, false
}

func enabledMethods(sshd SSHD, pam PAM) []int {

	var out []int

	if sshd.Get("pubkeyauthentication") == "yes" {
		out = append(out, 1)
	}
	if sshd.Get("passwordauthentication") == "yes" {
		out = append(out, 1)
	}
	if sshd.Get("kbdinteractiveauthentication") == "yes" {
		n := 1
		if hasSecondFactor(pam, "sshd") {
			n = 2
		}
		out = append(out, n)
	}

	return out
}

func authenticationMethods(sshd SSHD, pam PAM) int {

	value := sshd.Get("authenticationmethods")
	if value == "" || value == "any" {
		return 0
	}

	fewest := 0

	for _, list := range strings.Fields(value) {

		sum := 0
		for _, method := range strings.Split(list, ",") {
			method, _, _ = strings.Cut(method, ":")
			n := 1
			if method == "keyboard-interactive" && hasSecondFactor(pam, "sshd") {
				n = 2
			}
			sum += n
		}

		if fewest == 0 || sum < fewest {
			fewest = sum
		}
	}

	return fewest
}

func hasSecondFactor(pam PAM, service string) bool {

	for _, r := range pam.Stack(service, "auth") {
		if secondFactorModules[r.Module] && r.Control != "optional" && r.Control != "sufficient" {
			return true
		}
	}

	return false
}

func worst(decisions ...verdict.Judgement) verdict.Judgement {

	rank := map[verdict.Status]int{verdict.NonCompliant: 3, verdict.NotEvaluable: 2, verdict.Compliant: 1}
	best := verdict.Judgement{}

	for _, d := range decisions {
		if rank[d.Status] > rank[best.Status] {
			best = d
		}
	}

	return best
}

type EV03Input struct {
	Settings Settings
	PAM      PAM

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

var passwordServices = []string{"sshd", "login", "gdm-password", "lightdm", "sddm"}

const (
	faillockDeny   = 3
	faillockUnlock = 600
)

type Lockout struct {
	Service    string
	Module     string
	Deny       int
	UnlockSecs int
	Problem    catalog.Message
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}

	paths, unknown := passwordPaths(in.Settings, in.PAM)

	var failing []catalog.Message
	var judged []string

	for _, service := range paths {

		l := lockoutOf(service, in.PAM, in.Settings)
		judged = append(judged, service)

		switch {
		case !l.Problem.IsZero():
			unknown = append(unknown, catalog.Says("item.name_detail", "name", service, "detail", l.Problem))
		case l.Module == "":
			failing = append(failing, catalog.Says("opacc6.no_lockout_module", "service", service))
		case l.Deny == 0:
			failing = append(failing, catalog.Says("opacc6.without_deny", "service", service, "module", l.Module))
		case l.Deny > in.MaxAttempts:
			failing = append(failing, catalog.Says("opacc6.deny_too_high", "service", service, "module", l.Module, "deny", l.Deny, "max", in.MaxAttempts))
		case l.UnlockSecs > 0:
			failing = append(failing, catalog.Says("opacc6.unlocks_by_itself", "service", service, "module", l.Module, "seconds", l.UnlockSecs))
		}
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings_semicolon", "list", unknown))
	}

	if len(judged) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_login_path_accepts_passwords"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_lock_after_at_most_b_failed_attempts_u", "a", judged, "b", in.MaxAttempts))
}

func passwordPaths(settings Settings, pam PAM) (paths []string, unknown []catalog.Message) {

	for _, service := range passwordServices {

		if !pam.Has(service) {
			continue
		}

		if service != "sshd" {
			paths = append(paths, service)
			continue
		}

		sshd := settings.SSHD()

		switch sshd.Status {
		case fact.SourceAbsent:

			continue
		case fact.SourceRead:
		default:
			unknown = append(unknown, catalog.Says("opacc6.sshd_not_read", "error", sshd.Error))
			continue
		}

		if sshd.Get("passwordauthentication") == "yes" || (sshd.Get("kbdinteractiveauthentication") == "yes" && sshd.Get("usepam") == "yes") {
			paths = append(paths, service)
		}
	}

	return paths, unknown
}

func lockoutOf(service string, pam PAM, settings Settings) Lockout {

	l := Lockout{Service: service}

	for _, r := range pam.Stack(service, "auth") {

		if r.Control == "optional" || (r.Module != "pam_faillock.so" && r.Module != "pam_tally2.so") {
			continue
		}

		l.Module = r.Module

		if r.Module == "pam_tally2.so" {
			l.Deny, l.Problem = intArg(r, "deny", 0)
			if l.Problem.IsZero() {
				l.UnlockSecs, l.Problem = unlockArg(r, 0)
			}
			return l
		}

		deny, unlock := faillockDeny, faillockUnlock

		if v, unreadable, _ := settings.Lookup("/etc/security/faillock.conf", "", "deny"); len(unreadable) > 0 {
			l.Problem = catalog.Says("opacc6.unreadable", "file", "faillock.conf")
			return l
		} else if v.Found {
			n, err := strconv.Atoi(v.Value)
			if err != nil {
				l.Problem = catalog.Raw("faillock.conf deny=" + v.Value)
				return l
			}
			deny = n
		}

		if v, _, _ := settings.Lookup("/etc/security/faillock.conf", "", "unlock_time"); v.Found {
			n, ok := unlockValue(v.Value)
			if !ok {
				l.Problem = catalog.Raw("faillock.conf unlock_time=" + v.Value)
				return l
			}
			unlock = n
		}

		if l.Deny, l.Problem = intArg(r, "deny", deny); l.Problem.IsZero() {
			l.UnlockSecs, l.Problem = unlockArg(r, unlock)
		}

		return l
	}

	return l
}

func intArg(r fact.PAMRule, name string, def int) (int, catalog.Message) {

	v, found := Arg(r, name)
	if !found {
		return def, catalog.Message{}
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, catalog.Raw(fmt.Sprintf("%s %s=%s", r.Module, name, v))
	}

	return n, catalog.Message{}
}

func unlockArg(r fact.PAMRule, def int) (int, catalog.Message) {

	v, found := Arg(r, "unlock_time")
	if !found {
		return def, catalog.Message{}
	}

	n, ok := unlockValue(v)
	if !ok {
		return 0, catalog.Raw(fmt.Sprintf("%s unlock_time=%s", r.Module, v))
	}

	return n, catalog.Message{}
}

func unlockValue(v string) (int, bool) {

	if v == "never" {
		return 0, true
	}

	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

const attemptInterval = 15 * time.Minute

type EV04Input struct {
	Failures []source.Failure
	Lockouts []source.Lockout
	Log      passes.AuthLog

	MaxAttempts        int
	MaxAttemptsProblem catalog.Message
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if !in.MaxAttemptsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAttemptsProblem)
	}

	byAccount := map[string][]time.Time{}
	for _, f := range in.Failures {
		byAccount[f.Account] = append(byAccount[f.Account], f.Time)
	}

	locked := map[string]bool{}
	for _, l := range in.Lockouts {
		locked[l.Account] = true
	}

	var offenders []catalog.Message
	worst := 0

	for account, times := range byAccount {

		n := maxWithin(times, attemptInterval)
		worst = max(worst, n)

		if n > in.MaxAttempts && !locked[account] {
			offenders = append(offenders, catalog.Says("opacc6.failures_within", "account", account, "count", n, "minutes", int(attemptInterval.Minutes())))
		}
	}

	if len(offenders) > 0 {
		catalog.SortMessages(offenders)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.more_than_a_failed_attempts_without_a_lo", "a", in.MaxAttempts, "b", offenders))
	}

	if len(in.Failures) == 0 {
		if !in.Log.Reaches {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.failed_attempts_cannot_be_seen_a", "a", in.Log.Detail))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_failed_attempt_in_the_window"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_failed_attempts_on_b_accounts_at_most", "a", len(in.Failures), "b", len(byAccount), "c", worst, "d", int(attemptInterval.Minutes())))
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

type Accounts struct {
	Snapshot *fact.IdentitySnapshot
	Records  []fact.IdentityRecord
}

func (a Accounts) Gap() (verdict.Judgement, bool) {
	return passes.IdentityGap(a.Snapshot, a.Records)
}

type EV05Input struct {
	Accounts Accounts
	Settings Settings
	Today    time.Time

	MaxAge        int
	MaxAgeProblem catalog.Message
}

func JudgeEV05(in EV05Input) verdict.Judgement {

	if gap, found := in.Accounts.Gap(); found {
		return gap
	}
	if !in.MaxAgeProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxAgeProblem)
	}

	var failing, unknown []catalog.Message
	examined := 0

	for _, a := range in.Accounts.Records {

		disabled, known := opacc1.IsDisabled(a, in.Today)

		if !known {
			unknown = append(unknown, catalog.Says("opacc6.login_unknown", "account", a.AccountName))
			continue
		}
		if disabled {
			continue
		}

		examined++

		if a.PasswordState == fact.PasswordSet || a.PasswordState == fact.PasswordOther || a.PasswordState == fact.PasswordEmpty {
			f, u := passwordAge(a, in.Today, in.MaxAge)
			failing, unknown = append(failing, f...), append(unknown, u...)
		}

		switch {
		case a.AuthorizedKeys == nil:
			unknown = append(unknown, catalog.Says("opacc6.keys_unknown", "account", a.AccountName))
		case *a.AuthorizedKeys > 0 && a.AuthorizedKeysChanged == "":
			unknown = append(unknown, catalog.Says("opacc6.keys_change_unknown", "account", a.AccountName))
		case *a.AuthorizedKeys > 0:
			changed, err := time.Parse(time.RFC3339, a.AuthorizedKeysChanged)
			if err != nil {
				unknown = append(unknown, catalog.Raw(a.AccountName+": authorized_keys_changed "+a.AuthorizedKeysChanged))
			} else if age := days(in.Today.Sub(changed)); age > in.MaxAge {
				failing = append(failing, catalog.Says("opacc6.keys_old", "account", a.AccountName, "keys", *a.AuthorizedKeys, "days", age))
			}
		}
	}

	if f := loginDefsMax(in.Settings, in.MaxAge); !f.IsZero() {
		failing = append(failing, f)
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.older_than_p_04_a_days_b", "a", strconv.Itoa(in.MaxAge), "b", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_accounts_that_can_log_in_every_credent", "a", examined, "b", in.MaxAge))
}

func passwordAge(a fact.IdentityRecord, today time.Time, maxAge int) (failing, unknown []catalog.Message) {

	switch {
	case a.PasswordChangeForced:
	case a.PasswordChanged == "":
		unknown = append(unknown, catalog.Says("opacc6.password_change_unknown", "account", a.AccountName))
	default:
		changed, err := time.Parse("2006-01-02", a.PasswordChanged)
		if err != nil {
			unknown = append(unknown, catalog.Raw(a.AccountName+": password_changed "+a.PasswordChanged))
		} else if age := days(today.Sub(changed)); age > maxAge {
			failing = append(failing, catalog.Says("opacc6.password_old", "account", a.AccountName, "days", age))
		}
	}

	switch {
	case a.PasswordMaxDays == nil:
		failing = append(failing, catalog.Says("opacc6.password_never_expires", "account", a.AccountName))
	case *a.PasswordMaxDays > maxAge:
		failing = append(failing, catalog.Says("opacc6.password_expires_after", "account", a.AccountName, "days", *a.PasswordMaxDays))
	}

	return failing, unknown
}

func loginDefsMax(settings Settings, maxAge int) catalog.Message {

	if _, found := settings.Gap(); found {
		return catalog.Message{}
	}

	v, unreadable, seen := settings.Lookup("/etc/login.defs", "", "PASS_MAX_DAYS")

	if !seen || len(unreadable) > 0 {
		return catalog.Message{}
	}

	for _, f := range settings.Files {
		if f.Source == "/etc/login.defs" && f.Status == fact.SourceAbsent {
			return catalog.Message{}
		}
	}

	if !v.Found {
		return catalog.Says("opacc6.no_pass_max_days")
	}

	n, err := strconv.Atoi(v.Value)
	if err != nil || n > maxAge || n < 0 {
		return catalog.Says("opacc6.pass_max_days", "value", v.Value)
	}

	return catalog.Message{}
}

func days(d time.Duration) int {
	return int(d.Hours() / 24)
}

const RegisterParam = "P-12"

type Notice struct {
	Account string
	At      time.Time
	Reason  string
}

func ParseRegister(rows []string) ([]Notice, catalog.Message) {

	var out []Notice

	for _, row := range rows {

		cells := strings.Split(row, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) < 2 || cells[0] == "" {
			return nil, catalog.Says("opacc6.register_row", "param", RegisterParam, "row", row)
		}

		at, err := time.Parse(time.RFC3339, cells[1])
		if err != nil {
			if at, err = time.Parse("2006-01-02", cells[1]); err != nil {
				return nil, catalog.Says("opacc6.register_date", "param", RegisterParam, "row", row, "value", cells[1])
			}
		}

		n := Notice{Account: cells[0], At: at}
		if len(cells) > 2 {
			n.Reason = cells[2]
		}
		out = append(out, n)
	}

	return out, catalog.Message{}
}

type EV06Input struct {
	History map[string]history.Account
	Now     time.Time

	Notices        []Notice
	NoticesProblem catalog.Message

	MaxHours        int
	MaxHoursProblem catalog.Message
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if !in.NoticesProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.NoticesProblem)
	}
	if !in.MaxHoursProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxHoursProblem)
	}

	limit := time.Duration(in.MaxHours) * time.Hour
	var late, unknown, onTime []catalog.Message

	for _, n := range in.Notices {

		a, here := in.History[n.Account]
		if !here {
			continue
		}

		var end *time.Time
		switch {
		case a.DeletedAt != nil:
			end = a.DeletedAt
		case a.DisabledSince != nil:
			end = a.DisabledSince
		}

		where := catalog.Raw(fmt.Sprintf("%s (%s %s)", n.Account, n.Reason, n.At.UTC().Format(time.RFC3339)))

		switch {
		case end == nil:
			if took := in.Now.Sub(n.At); took > limit {
				late = append(late, catalog.Says("opacc6.still_enabled", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, catalog.Says("opacc6.within_deadline", "notice", where))
			}
		case !end.After(n.At):
			onTime = append(onTime, catalog.Says("opacc6.already_disabled", "notice", where))
		case a.DeletedAt == nil && !a.DisabledObserved:

			if took := end.Sub(n.At); took > limit {
				unknown = append(unknown, catalog.Says("opacc6.disabled_when_unknown", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		default:

			if took := end.Sub(n.At); took > limit {
				late = append(late, catalog.Says("opacc6.disabled_after", "notice", where, "hours", int(took.Hours())))
			} else {
				onTime = append(onTime, where)
			}
		}
	}

	if len(late) > 0 {
		catalog.SortMessages(late)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.not_disabled_within_a_hours_b", "a", in.MaxHours, "b", late))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	if len(onTime) == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_notice_in_the_register_for_an_account"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.disabled_within_a_hours_of_the_notice_b", "a", in.MaxHours, "b", onTime))
}

var channels = map[string]string{source.MethodSSHD: "ssh"}

type EV07Input struct {
	Logins []source.Login

	Log passes.AuthLog

	Channels        []string
	ChannelsProblem catalog.Message
}

func JudgeEV07(in EV07Input) verdict.Judgement {

	if !in.ChannelsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.ChannelsProblem)
	}

	authorized := map[string]bool{}
	for _, c := range in.Channels {
		authorized[strings.ToLower(strings.TrimSpace(c))] = true
	}

	used := map[string]int{}
	outside := map[[3]string]int{}

	for _, l := range in.Logins {

		channel, remote := channels[l.Method]
		if !remote {
			continue
		}

		used[channel]++
		if !authorized[channel] {
			outside[[3]string{channel, l.Account, l.SourceIP}]++
		}
	}

	if len(outside) > 0 {
		var list []catalog.Message
		for k, n := range outside {
			list = append(list, catalog.Says("opacc6.login_through", "channel", k[0], "account", k[1], "ip", k[2], "count", n))
		}
		catalog.SortMessages(list)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.remote_logins_through_channels_not_in_p", "a", list))
	}

	if len(used) == 0 {
		if !in.Log.Reaches {
			return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.remote_logins_cannot_be_seen_a", "a", in.Log.Detail))
		}
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.no_remote_login_in_the_window"))
	}

	var list []catalog.Message
	for c, n := range used {
		list = append(list, catalog.Says("opacc6.channel_logins", "channel", c, "count", n))
	}
	catalog.SortMessages(list)

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.remote_logins_only_through_p_07_channels", "a", list))
}

type EV08Input struct {
	Listening Listening

	Rows        []string
	RowsProblem catalog.Message
}

type channelRow struct {
	encrypted string
	constant  string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if gap, found := in.Listening.Gap(); found {
		return gap
	}
	if !in.RowsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.RowsProblem)
	}

	rows := map[string]channelRow{}
	for _, r := range in.Rows {
		cells := strings.Split(r, "|")
		for i := range cells {
			cells[i] = strings.ToLower(strings.TrimSpace(cells[i]))
		}
		for len(cells) < 4 {
			cells = append(cells, "")
		}
		rows[cells[0]] = channelRow{encrypted: cells[1], constant: cells[3]}
	}

	channels, other := in.Listening.Channels()

	var failing, unknown []catalog.Message
	var fine []string

	for _, c := range channels {

		where := catalog.Says("opacc6.channel_where", "name", c.Name, "processes", strings.Join(c.Processes, ","), "ports", fmt.Sprint(c.Ports))
		row, listed := rows[c.Name]

		switch {
		case !listed:
			failing = append(failing, catalog.Says("opacc6.no_p07_row", "channel", where))
			continue
		case !c.Encrypted:
			failing = append(failing, catalog.Says("opacc6.not_encrypted", "channel", where))
			continue
		}

		if row.constant == "no" {
			switch state := enablement(c); state {
			case "enabled":
				failing = append(failing, catalog.Says("opacc6.enabled_at_boot", "channel", where))
				continue
			case "":
				unknown = append(unknown, catalog.Says("opacc6.boot_unknown", "channel", where))
				continue
			}
		}

		fine = append(fine, c.Name)
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("findings_semicolon", "list", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	reason := catalog.Says("opacc6.no_channel_listening")
	if len(fine) > 0 {
		reason = catalog.Says("opacc6.channels_fine", "list", fine)
	}
	if len(other) > 0 {
		reason = catalog.Says("opacc6.other_listeners", "reason", reason, "count", len(other))
	}

	return verdict.Explain(verdict.Compliant, "", reason)
}

func enablement(c Channel) string {

	if len(c.Units) == 0 {
		return ""
	}

	state := "disabled"

	for _, e := range c.Enabled {
		switch e {
		case "enabled", "enabled-runtime", "alias", "linked", "linked-runtime":
			return "enabled"
		case "disabled", "masked", "masked-runtime", "static", "indirect", "generated", "transient":
		default:
			state = ""
		}
	}

	return state
}

type Sudoers struct {
	Snapshot *fact.SudoersSnapshot
	Grants   []fact.SudoGrant
}

type EV09Input struct {
	Sudoers Sudoers
	PAM     PAM

	Points        []string
	PointsProblem catalog.Message
}

type Finding struct {
	Point  string
	Detail catalog.Message
}

var undefinedAlias = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func JudgeEV09(in EV09Input) verdict.Judgement {

	if !in.PointsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.PointsProblem)
	}

	listed := map[string]bool{}
	for _, p := range in.Points {
		listed[strings.ToLower(strings.TrimSpace(p))] = true
	}

	sudoListed := false
	for p := range listed {
		if p == "sudo" || strings.HasPrefix(p, "sudo:") {
			sudoListed = true
		}
	}

	var findings []Finding
	var unknown []catalog.Message

	switch {
	case !sudoListed:
	case in.Sudoers.Snapshot == nil:
		unknown = append(unknown, catalog.Says("gap.no_fact", "fact", "sudoers_snapshot"))
	case in.Sudoers.Snapshot.Status == fact.SourceAbsent:

	case in.Sudoers.Snapshot.Status != fact.SourceRead:
		unknown = append(unknown, catalog.Says("opacc6.unreadable", "file", "sudoers"))
	case len(in.Sudoers.Grants) < in.Sudoers.Snapshot.RecordsEmitted:
		unknown = append(unknown, catalog.Says("opacc6.sudoers_incomplete", "got", len(in.Sudoers.Grants), "want", in.Sudoers.Snapshot.RecordsEmitted))
	default:
		f, u := sudoFindings(in.Sudoers)
		findings, unknown = append(findings, f...), append(unknown, u...)

		if b := in.Sudoers.Snapshot.BlindSpots; b > 0 {
			unknown = append(unknown, catalog.Says("opacc6.sudoers_blind", "count", b, "reasons", strings.Join(in.Sudoers.Snapshot.BlindSpotReasons, "; ")))
		}
	}

	if listed["su"] {
		f, u := suFindings(in.PAM)
		findings, unknown = append(findings, f...), append(unknown, u...)
	}

	var failing []catalog.Message
	for _, f := range findings {
		if listed[strings.ToLower(f.Point)] || (f.Point == "sudo" && sudoListed) {
			failing = append(failing, catalog.Says("opacc6.point_detail", "point", f.Point, "detail", f.Detail))
		}
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.no_re_authentication_at_a", "a", failing))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.re_authentication_required_at_a", "a", in.Points))
}

func sudoFindings(s Sudoers) (findings []Finding, unknown []catalog.Message) {

	for _, g := range s.Grants {

		if (g.SubjectKind == "user" && g.Subject == "root") || (g.SubjectKind == "uid" && g.Subject == "0") {
			continue
		}

		where := fmt.Sprintf("%s %s, %s:%d", g.SubjectKind, g.Subject, g.File, g.Line)

		for _, cmd := range g.NoPasswdCommands {
			switch {
			case cmd == "ALL":
				findings = append(findings, Finding{Point: "sudo", Detail: catalog.Says("opacc6.nopasswd_all", "where", where)})
			case undefinedAlias.MatchString(cmd):
				unknown = append(unknown, catalog.Says("opacc6.undefined_alias", "alias", cmd, "where", where))
			default:
				findings = append(findings, Finding{Point: "sudo:" + commandPath(cmd), Detail: catalog.Says("opacc6.nopasswd", "where", where)})
			}
		}
	}

	for _, d := range s.Snapshot.Defaults {

		point := "sudo"
		if strings.HasPrefix(d.Binding, "!") {
			point = "sudo:" + commandPath(strings.TrimPrefix(d.Binding, "!"))
		}
		where := fmt.Sprintf("Defaults%s, %s:%d", d.Binding, d.File, d.Line)

		setting := strings.ReplaceAll(d.Setting, " ", "")

		switch {
		case setting == "!authenticate":
			findings = append(findings, Finding{Point: point, Detail: catalog.Says("opacc6.not_authenticate", "where", where)})
		case strings.HasPrefix(setting, "timestamp_timeout="):
			if n, err := strconv.ParseFloat(strings.TrimPrefix(setting, "timestamp_timeout="), 64); err == nil && n < 0 {
				findings = append(findings, Finding{Point: point, Detail: catalog.Says("opacc6.cached_forever", "where", where)})
			}
		}
	}

	return findings, unknown
}

func commandPath(cmd string) string {
	path, _, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	return path
}

func suFindings(pam PAM) (findings []Finding, unknown []catalog.Message) {

	if gap, found := pam.Gap(); found {
		return nil, []catalog.Message{catalog.Says("item.name_detail", "name", "su", "detail", gap.Message)}
	}

	for _, service := range []string{"su", "su-l"} {
		for _, r := range pam.Stack(service, "auth") {
			if _, trust := Arg(r, "trust"); r.Module == "pam_wheel.so" && trust {
				findings = append(findings, Finding{Point: "su", Detail: catalog.Says("opacc6.wheel_trust", "file", r.File, "line", r.Line)})
			}
		}
	}

	return findings, nil
}

type EV10Input struct {
	Accounts Accounts
	Today    time.Time

	LastAlert map[string]time.Time

	MaxIdle        int
	MaxIdleProblem catalog.Message
}

func JudgeEV10(in EV10Input) verdict.Judgement {

	if gap, found := in.Accounts.Gap(); found {
		return gap
	}
	if !in.MaxIdleProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MaxIdleProblem)
	}

	var idle, unknown []catalog.Message
	examined := 0

	for _, a := range in.Accounts.Records {

		disabled, known := opacc1.IsDisabled(a, in.Today)
		if !known {
			unknown = append(unknown, catalog.Says("opacc6.login_unknown", "account", a.AccountName))
			continue
		}
		if disabled {
			continue
		}
		examined++

		last, since := lastUse(a.LastLogin, in.LastAlert[a.AccountName]), "opacc6.idle_used"

		if last.IsZero() {
			last, since = newestDate(a.PasswordChanged, a.AuthorizedKeysChanged), "opacc6.idle_never_used"
		}

		if last.IsZero() {
			unknown = append(unknown, catalog.Says("opacc6.never_used_no_date", "account", a.AccountName))
			continue
		}

		if d := days(in.Today.Sub(last)); d > in.MaxIdle {
			idle = append(idle, catalog.Says(since, "account", a.AccountName, "days", d))
		}
	}

	if len(idle) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.enabled_and_unused_for_more_than_a_days", "a", in.MaxIdle, "b", idle))
	}

	if len(unknown) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("findings_semicolon", "list", unknown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_accounts_that_can_log_in_all_used_with", "a", examined, "b", in.MaxIdle))
}

func lastUse(lastLogin string, alert time.Time) time.Time {

	last := alert

	if t, err := time.Parse(time.RFC3339, lastLogin); err == nil && t.After(last) {
		last = t
	}

	return last
}

func newestDate(date, stamp string) time.Time {

	var newest time.Time

	if t, err := time.Parse("2006-01-02", date); err == nil {
		newest = t
	}
	if t, err := time.Parse(time.RFC3339, stamp); err == nil && t.After(newest) {
		newest = t
	}

	return newest
}

const (
	CriterionLength    = "longitud_minima"
	CriterionClasses   = "clases_de_caracteres"
	CriterionHistory   = "historial"
	CriterionBlocklist = "lista_de_bloqueo"
)

type EV11Input struct {
	PAM      PAM
	Settings Settings

	Minimums        map[string]int
	MinimumsProblem catalog.Message
}

type Quality struct {
	Mechanism string
	Values    map[string]int
}

func JudgeEV11(in EV11Input) verdict.Judgement {

	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if !in.MinimumsProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.MinimumsProblem)
	}

	stack := in.PAM.Stack("passwd", "password")
	if len(stack) == 0 {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.no_password_stack_for_passwd_in_etc_pam"))
	}

	q, problem := qualityOf(stack, in.Settings)
	if !problem.IsZero() {
		return passes.Gap(verdict.CauseCollection, problem)
	}

	var failing, met []catalog.Message

	for _, criterion := range []string{CriterionLength, CriterionClasses, CriterionHistory, CriterionBlocklist} {

		minimum, asked := in.Minimums[criterion]
		if !asked {
			continue
		}

		got := q.Values[criterion]
		item := catalog.Says("opacc6.criterion", "criterion", catalog.Says("opacc6.criterion."+criterion), "got", got, "minimum", minimum)

		if got < minimum {
			failing = append(failing, item)
		} else {
			met = append(met, item)
		}
	}

	if len(failing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.a_b", "a", q.Mechanism, "b", failing))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.a_b", "a", q.Mechanism, "b", met))
}

func qualityOf(stack []fact.PAMRule, settings Settings) (Quality, catalog.Message) {

	q := Quality{Values: map[string]int{}}

	var checker, unix, history *fact.PAMRule
	for i := range stack {
		r := &stack[i]
		switch r.Module {
		case "pam_pwquality.so", "pam_cracklib.so":
			if checker == nil {
				checker = r
			}
		case "pam_unix.so":
			if unix == nil {
				unix = r
			}
		case "pam_pwhistory.so":
			if history == nil {
				history = r
			}
		}
	}

	switch {
	case checker != nil && checker.Module == "pam_pwquality.so":
		q.Mechanism = "pam_pwquality"
		get := func(name string, def int) (int, catalog.Message) {
			return pwqualityValue(*checker, settings, name, def)
		}

		var p catalog.Message
		if q.Values[CriterionLength], p = get("minlen", 8); !p.IsZero() {
			return q, p
		}
		classes, p := pwqualityClasses(get)
		if !p.IsZero() {
			return q, p
		}
		q.Values[CriterionClasses] = classes
		if q.Values[CriterionBlocklist], p = get("dictcheck", 1); !p.IsZero() {
			return q, p
		}
		if q.Values[CriterionBlocklist] > 0 {
			q.Values[CriterionBlocklist] = 1
		}

	case checker != nil:
		q.Mechanism = "pam_cracklib"
		get := func(name string, def int) (int, catalog.Message) { return ruleInt(*checker, name, def) }

		var p catalog.Message
		if q.Values[CriterionLength], p = get("minlen", 9); !p.IsZero() {
			return q, p
		}
		classes, p := pwqualityClasses(get)
		if !p.IsZero() {
			return q, p
		}
		q.Values[CriterionClasses] = classes
		q.Values[CriterionBlocklist] = 1

	case unix != nil:

		q.Mechanism = "pam_unix"
		q.Values[CriterionLength] = 1
		if _, obscure := Arg(*unix, "obscure"); obscure {
			n, p := ruleInt(*unix, "minlen", 6)
			if !p.IsZero() {
				return q, p
			}
			q.Values[CriterionLength] = n
		}

	default:
		q.Mechanism = "-"
	}

	switch {
	case history != nil:
		n, p := pwhistoryValue(*history, settings)
		if !p.IsZero() {
			return q, p
		}
		q.Values[CriterionHistory] = n
	case unix != nil:
		n, p := ruleInt(*unix, "remember", 0)
		if !p.IsZero() {
			return q, p
		}
		q.Values[CriterionHistory] = n
	}

	return q, catalog.Message{}
}

func pwqualityClasses(get func(string, int) (int, catalog.Message)) (int, catalog.Message) {

	classes, p := get("minclass", 0)
	if !p.IsZero() {
		return 0, p
	}

	required := 0
	for _, credit := range []string{"dcredit", "ucredit", "lcredit", "ocredit"} {
		n, p := get(credit, 0)
		if !p.IsZero() {
			return 0, p
		}
		if n < 0 {
			required++
		}
	}

	return min(max(classes, required), 4), catalog.Message{}
}

func pwqualityValue(r fact.PAMRule, settings Settings, name string, def int) (int, catalog.Message) {

	if v, found := Arg(r, name); found {
		return atoi(r.Module, name, v)
	}

	v, unreadable, _ := settings.Lookup("/etc/security/pwquality.conf", "", name)
	if len(unreadable) > 0 {
		return 0, catalog.Says("opacc6.unreadable", "file", strings.Join(unreadable, ", "))
	}
	if v.Found {
		return atoi(v.Source, name, v.Value)
	}

	return def, catalog.Message{}
}

func pwhistoryValue(r fact.PAMRule, settings Settings) (int, catalog.Message) {

	if v, found := Arg(r, "remember"); found {
		return atoi(r.Module, "remember", v)
	}

	v, unreadable, _ := settings.Lookup("/etc/security/pwhistory.conf", "", "remember")
	if len(unreadable) > 0 {
		return 0, catalog.Says("opacc6.unreadable", "file", "pwhistory.conf")
	}
	if v.Found {
		return atoi(v.Source, "remember", v.Value)
	}

	return 10, catalog.Message{}
}

func ruleInt(r fact.PAMRule, name string, def int) (int, catalog.Message) {
	if v, found := Arg(r, name); found {
		return atoi(r.Module, name, v)
	}
	return def, catalog.Message{}
}

func atoi(where, name, v string) (int, catalog.Message) {
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, catalog.Says("opacc6.not_a_number", "where", where, "name", name, "value", v)
	}
	return n, catalog.Message{}
}

const (
	ExposureVersion      = "sshd:version_software"
	ExposureDistribution = "sshd:version_distribucion"
	ExposureAddendum     = "sshd:version_addendum"
	ExposureBanner       = "sshd:banner_previo"
)

type EV12Input struct {
	Settings Settings

	Allowed        []string
	AllowedProblem catalog.Message
}

func JudgeEV12(in EV12Input) verdict.Judgement {

	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if !in.AllowedProblem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, in.AllowedProblem)
	}

	sshd := in.Settings.SSHD()

	switch sshd.Status {
	case fact.SourceAbsent:
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.sshd_not_installed_no_authentication_ser"))
	case fact.SourceRead:
	case "":
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.the_configuration_read_has_no_sshd_t"))
	default:
		return passes.Gap(verdict.CauseCollection, catalog.Says("opacc6.sshd_t_a", "a", sshd.Error))
	}

	exposures := []string{ExposureVersion}

	version := ""
	if v, ok := in.Settings.Command(" -V"); ok && v.Status == fact.SourceRead && len(v.Entries) > 0 {
		version = v.Entries[0].Value
	}

	if banner := sshd.Get("debianbanner"); banner == "yes" || (banner == "" && (strings.Contains(version, "Ubuntu") || strings.Contains(version, "Debian"))) {
		exposures = append(exposures, ExposureDistribution)
	}
	if v := sshd.Get("versionaddendum"); v != "" && v != "none" {
		exposures = append(exposures, ExposureAddendum)
	}
	if v := sshd.Get("banner"); v != "" && v != "none" {
		exposures = append(exposures, ExposureBanner)
	}

	allowed := map[string]bool{}
	for _, a := range in.Allowed {
		allowed[strings.TrimSpace(a)] = true
	}

	var shown []string
	for _, e := range exposures {
		if !allowed[e] {
			shown = append(shown, e)
		}
	}

	if len(shown) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc6.shown_before_authenticating_and_not_in_p", "a", shown))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc6.sshd_shows_only_what_p_11_allows_a", "a", exposures))
}

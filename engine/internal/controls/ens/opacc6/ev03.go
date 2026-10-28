package opacc6

import (
	"fmt"
	"sort"
	"strconv"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

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

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

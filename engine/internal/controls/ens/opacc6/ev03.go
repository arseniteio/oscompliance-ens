package opacc6

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV03Input struct {
	Settings Settings
	PAM      PAM

	MaxAttempts        int
	MaxAttemptsProblem string
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
	Problem    string
}

func JudgeEV03(in EV03Input) verdict.Judgement {

	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+in.MaxAttemptsProblem)
	}

	paths, unknown := passwordPaths(in.Settings, in.PAM)

	var failing, judged []string

	for _, service := range paths {

		l := lockoutOf(service, in.PAM, in.Settings)
		judged = append(judged, service)

		switch {
		case l.Problem != "":
			unknown = append(unknown, service+": "+l.Problem)
		case l.Module == "":
			failing = append(failing, service+": no lockout module")
		case l.Deny == 0:
			failing = append(failing, fmt.Sprintf("%s: %s without deny", service, l.Module))
		case l.Deny > in.MaxAttempts:
			failing = append(failing, fmt.Sprintf("%s: %s deny=%d, P-05 allows %d", service, l.Module, l.Deny, in.MaxAttempts))
		case l.UnlockSecs > 0:
			failing = append(failing, fmt.Sprintf("%s: %s unlocks by itself after %d s", service, l.Module, l.UnlockSecs))
		}
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}

	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unknown, "; "))
	}

	if len(judged) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no login path accepts passwords"}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%s lock after at most %d failed attempts until unlocked by an administrator", strings.Join(judged, ", "), in.MaxAttempts),
	}
}

func passwordPaths(settings Settings, pam PAM) (paths, unknown []string) {

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
			unknown = append(unknown, "sshd: effective configuration not read: "+sshd.Error)
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
			if l.Problem == "" {
				l.UnlockSecs, l.Problem = unlockArg(r, 0)
			}
			return l
		}

		deny, unlock := faillockDeny, faillockUnlock

		if v, unreadable, _ := settings.Lookup("/etc/security/faillock.conf", "", "deny"); len(unreadable) > 0 {
			l.Problem = "faillock.conf unreadable"
			return l
		} else if v.Found {
			n, err := strconv.Atoi(v.Value)
			if err != nil {
				l.Problem = "faillock.conf deny=" + v.Value
				return l
			}
			deny = n
		}

		if v, _, _ := settings.Lookup("/etc/security/faillock.conf", "", "unlock_time"); v.Found {
			n, ok := unlockValue(v.Value)
			if !ok {
				l.Problem = "faillock.conf unlock_time=" + v.Value
				return l
			}
			unlock = n
		}

		if l.Deny, l.Problem = intArg(r, "deny", deny); l.Problem == "" {
			l.UnlockSecs, l.Problem = unlockArg(r, unlock)
		}

		return l
	}

	return l
}

func intArg(r fact.PAMRule, name string, def int) (int, string) {

	v, found := Arg(r, name)
	if !found {
		return def, ""
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Sprintf("%s %s=%s", r.Module, name, v)
	}

	return n, ""
}

func unlockArg(r fact.PAMRule, def int) (int, string) {

	v, found := Arg(r, "unlock_time")
	if !found {
		return def, ""
	}

	n, ok := unlockValue(v)
	if !ok {
		return 0, fmt.Sprintf("%s unlock_time=%s", r.Module, v)
	}

	return n, ""
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

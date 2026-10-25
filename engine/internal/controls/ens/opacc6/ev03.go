package opacc6

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV03Input is what EV-03 (attempt limit with effective lockout) needs.
type EV03Input struct {
	Settings Settings
	PAM      PAM

	// MaxAttempts is P-05; MaxAttemptsProblem says why it cannot be used.
	MaxAttempts        int
	MaxAttemptsProblem string
}

// passwordServices are the PAM services through which a person types a
// password: remote login, console login and the graphical greeters.
var passwordServices = []string{"sshd", "login", "gdm-password", "lightdm", "sddm"}

// faillockDefaults are pam_faillock's own defaults (faillock.conf(5)).
const (
	faillockDeny   = 3
	faillockUnlock = 600
)

// Lockout is how one login path limits failed attempts.
type Lockout struct {
	Service    string
	Module     string // pam_faillock.so, pam_tally2.so, "" for none
	Deny       int    // 0: no limit
	UnlockSecs int    // 0: only an administrator unlocks
	Problem    string // why the settings cannot be read
}

// JudgeEV03 judges EV-03 as described in catalog/docs/contracts/op.acc.6.md:
//
//  1. PAM or the configuration read unusable: NOT_EVALUABLE, COLLECTION.
//     P-05 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. Every password path in use is examined: sshd when it accepts
//     passwords (PasswordAuthentication or KbdInteractiveAuthentication),
//     login and the graphical greeters when they have a PAM file.
//  3. A path without a lockout module, with more attempts than P-05, or that
//     unlocks by itself after a time: NON_COMPLIANT. The ENS asks for a
//     specific intervention to reactivate the account.
//  4. A path whose settings cannot be read: NOT_EVALUABLE, COLLECTION.
//  5. Otherwise COMPLIANT, also when no path accepts passwords.
func JudgeEV03(in EV03Input) verdict.Judgement {

	// 1. Facts and parameter.
	if gap, found := in.PAM.Gap(); found {
		return gap
	}
	if gap, found := in.Settings.Gap(); found {
		return gap
	}
	if in.MaxAttemptsProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-05: "+in.MaxAttemptsProblem)
	}

	// 2. The paths in use.
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

	// 3. A path that lets attempts through.
	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: strings.Join(failing, "; ")}
	}

	// 4. A path we could not read.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unknown, "; "))
	}

	// 5. Every path locks after at most P-05 attempts until an administrator acts.
	if len(judged) == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no login path accepts passwords"}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%s lock after at most %d failed attempts until unlocked by an administrator", strings.Join(judged, ", "), in.MaxAttempts),
	}
}

// passwordPaths are the services of passwordServices in use; unknown says
// why sshd could not be decided.
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
			// A PAM file without sshd: nothing listens.
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

// lockoutOf reads the lockout of one service from its auth stack: the first
// pam_faillock or pam_tally2 rule that is not optional. pam_faillock takes
// its settings from the rule, then faillock.conf, then its defaults.
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

		// pam_faillock: the conf file first, the rule overrides.
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

// unlockValue: seconds, or "never" (only an administrator unlocks), as 0.
func unlockValue(v string) (int, bool) {

	if v == "never" {
		return 0, true
	}

	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

// sortedKeys returns the keys of a set in order.
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

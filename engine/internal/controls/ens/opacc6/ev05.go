package opacc6

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/controls/ens/opacc1"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

// Accounts is one identity pass of an agent (op.acc.1 EV-02 facts).
type Accounts struct {
	Snapshot *fact.IdentitySnapshot
	Records  []fact.IdentityRecord
}

// Gap says why the pass cannot be used.
func (a Accounts) Gap() (verdict.Judgement, bool) {
	return passes.IdentityGap(a.Snapshot, a.Records)
}

// EV05Input is what EV-05 (periodic credential change) needs.
type EV05Input struct {
	Accounts Accounts
	Settings Settings
	Today    time.Time

	// MaxAge is P-04 in days; MaxAgeProblem says why it cannot be used.
	MaxAge        int
	MaxAgeProblem string
}

// JudgeEV05 judges EV-05 as described in catalog/docs/contracts/op.acc.6.md.
// Every account that can still authenticate is examined, at any UID:
//
//  1. Identity pass unusable: NOT_EVALUABLE, COLLECTION. P-04 unusable:
//     NOT_EVALUABLE, CONFIGURATION.
//  2. A password older than P-04, or allowed to live longer (no maximum, or
//     a maximum above P-04): NON_COMPLIANT. A forced change at next login
//     is a fresh password.
//  3. Authorized keys unchanged for longer than P-04: NON_COMPLIANT. The
//     files' change time is when the newest key was written, so some key is
//     at least that old.
//  4. login.defs giving new accounts a maximum above P-04: NON_COMPLIANT.
//  5. An account whose state or ages cannot be known: NOT_EVALUABLE,
//     COLLECTION. Otherwise COMPLIANT.
func JudgeEV05(in EV05Input) verdict.Judgement {

	// 1. Facts and parameter.
	if gap, found := in.Accounts.Gap(); found {
		return gap
	}
	if in.MaxAgeProblem != "" {
		return passes.NotEvaluable(verdict.CauseConfiguration, "P-04: "+in.MaxAgeProblem)
	}

	var failing, unknown []string
	examined := 0

	for _, a := range in.Accounts.Records {

		disabled, known := opacc1.IsDisabled(a, in.Today)

		if !known {
			unknown = append(unknown, a.AccountName+": cannot tell whether it can log in")
			continue
		}
		if disabled {
			continue
		}

		examined++

		// 2. The password, when there is one to log in with.
		if a.PasswordState == fact.PasswordSet || a.PasswordState == fact.PasswordOther || a.PasswordState == fact.PasswordEmpty {
			f, u := passwordAge(a, in.Today, in.MaxAge)
			failing, unknown = append(failing, f...), append(unknown, u...)
		}

		// 3. The keys.
		switch {
		case a.AuthorizedKeys == nil:
			unknown = append(unknown, a.AccountName+": authorized keys unknown")
		case *a.AuthorizedKeys > 0 && a.AuthorizedKeysChanged == "":
			unknown = append(unknown, a.AccountName+": authorized keys change time unknown")
		case *a.AuthorizedKeys > 0:
			changed, err := time.Parse(time.RFC3339, a.AuthorizedKeysChanged)
			if err != nil {
				unknown = append(unknown, a.AccountName+": authorized_keys_changed "+a.AuthorizedKeysChanged)
			} else if age := days(in.Today.Sub(changed)); age > in.MaxAge {
				failing = append(failing, fmt.Sprintf("%s: %d SSH keys unchanged for %d days", a.AccountName, *a.AuthorizedKeys, age))
			}
		}
	}

	// 4. What new accounts get.
	if f := loginDefsMax(in.Settings, in.MaxAge); f != "" {
		failing = append(failing, f)
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "older than P-04 (" + strconv.Itoa(in.MaxAge) + " days): " + strings.Join(failing, "; ")}
	}

	// 5. Silence counts only for what could be read.
	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unknown, "; "))
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts that can log in, every credential changed within %d days and set to expire within them", examined, in.MaxAge),
	}
}

// passwordAge checks one usable password against P-04.
func passwordAge(a fact.IdentityRecord, today time.Time, maxAge int) (failing, unknown []string) {

	switch {
	case a.PasswordChangeForced:
	case a.PasswordChanged == "":
		unknown = append(unknown, a.AccountName+": date of the last password change unknown")
	default:
		changed, err := time.Parse("2006-01-02", a.PasswordChanged)
		if err != nil {
			unknown = append(unknown, a.AccountName+": password_changed "+a.PasswordChanged)
		} else if age := days(today.Sub(changed)); age > maxAge {
			failing = append(failing, fmt.Sprintf("%s: password %d days old", a.AccountName, age))
		}
	}

	switch {
	case a.PasswordMaxDays == nil:
		failing = append(failing, a.AccountName+": password never expires")
	case *a.PasswordMaxDays > maxAge:
		failing = append(failing, fmt.Sprintf("%s: password expires after %d days", a.AccountName, *a.PasswordMaxDays))
	}

	return failing, unknown
}

// loginDefsMax is the finding of login.defs PASS_MAX_DAYS, "" when it is
// within P-04 or not known. Without the setting shadow tools write no
// maximum: passwords of new accounts never expire.
func loginDefsMax(settings Settings, maxAge int) string {

	if _, found := settings.Gap(); found {
		return ""
	}

	v, unreadable, seen := settings.Lookup("/etc/login.defs", "", "PASS_MAX_DAYS")

	if !seen || len(unreadable) > 0 {
		return ""
	}

	for _, f := range settings.Files {
		if f.Source == "/etc/login.defs" && f.Status == fact.SourceAbsent {
			return ""
		}
	}

	if !v.Found {
		return "login.defs: no PASS_MAX_DAYS, new accounts get passwords that never expire"
	}

	n, err := strconv.Atoi(v.Value)
	if err != nil || n > maxAge || n < 0 {
		return "login.defs: PASS_MAX_DAYS " + v.Value + " for new accounts"
	}

	return ""
}

// days is a duration in whole days.
func days(d time.Duration) int {
	return int(d.Hours() / 24)
}

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
	MaxAgeProblem string
}

func JudgeEV05(in EV05Input) verdict.Judgement {

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

		if a.PasswordState == fact.PasswordSet || a.PasswordState == fact.PasswordOther || a.PasswordState == fact.PasswordEmpty {
			f, u := passwordAge(a, in.Today, in.MaxAge)
			failing, unknown = append(failing, f...), append(unknown, u...)
		}

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

	if f := loginDefsMax(in.Settings, in.MaxAge); f != "" {
		failing = append(failing, f)
	}

	if len(failing) > 0 {
		return verdict.Judgement{Status: verdict.NonCompliant, Reason: "older than P-04 (" + strconv.Itoa(in.MaxAge) + " days): " + strings.Join(failing, "; ")}
	}

	if len(unknown) > 0 {
		return passes.NotEvaluable(verdict.CauseCollection, strings.Join(unknown, "; "))
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts that can log in, every credential changed within %d days and set to expire within them", examined, in.MaxAge),
	}
}

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

func days(d time.Duration) int {
	return int(d.Hours() / 24)
}

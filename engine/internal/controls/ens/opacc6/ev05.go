package opacc6

import (
	"strconv"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
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

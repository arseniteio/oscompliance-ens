package opacc1

import (
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

const DefaultUIDMin = 1000

type EV04Input struct {
	Accounts        []fact.IdentityRecord
	AccountsProblem catalog.Message

	Declared    map[string]time.Time
	DeclaredSet bool

	DeadlineDays int
	UIDMin       int

	ConfigProblem catalog.Message

	Now time.Time
}

func JudgeEV04(in EV04Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if !in.AccountsProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.AccountsProblem)
	}

	today := in.Now.UTC().Truncate(24 * time.Hour)

	measured := 0
	var overdue []catalog.Message
	var unknown []string

	for _, account := range in.Accounts {

		if account.UID < in.UIDMin {
			continue
		}

		left, known := offboardingDate(account, in.Declared)

		if !known {
			continue
		}

		measured++

		disabled, known := IsDisabled(account, today)

		if disabled {
			continue
		}

		days := int(today.Sub(left.UTC().Truncate(24*time.Hour)).Hours() / 24)

		if days <= in.DeadlineDays {
			continue
		}

		if !known {
			unknown = append(unknown, account.AccountName)
			continue
		}

		overdue = append(overdue, catalog.Says("opacc1.account_days", "account", account.AccountName, "days", days))
	}

	if len(overdue) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev04.overdue", "days", in.DeadlineDays, "accounts", overdue))
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev04.keys_unknown", "accounts", unknown))
	}

	if measured == 0 && !in.DeclaredSet {
		return notEvaluable(verdict.CauseConfiguration, catalog.Says("opacc1.ev04.no_dates"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev04.in_time", "accounts", measured, "days", in.DeadlineDays))
}

func offboardingDate(account fact.IdentityRecord, declared map[string]time.Time) (time.Time, bool) {

	if date, ok := declared[account.AccountName]; ok {
		return date, true
	}

	if account.AccountExpires == "" {
		return time.Time{}, false
	}

	date, err := time.Parse("2006-01-02", account.AccountExpires)

	return date, err == nil
}

func IsDisabled(account fact.IdentityRecord, today time.Time) (disabled, known bool) {

	if strings.HasSuffix(account.Shell, "/nologin") || strings.HasSuffix(account.Shell, "/false") {
		return true, true
	}

	if account.AccountExpires != "" {
		if expires, err := time.Parse("2006-01-02", account.AccountExpires); err == nil && !expires.After(today) {
			return true, true
		}
	}

	if account.PasswordState != fact.PasswordLocked && account.PasswordState != fact.PasswordMissing {
		return false, true
	}

	if account.AuthorizedKeys == nil {
		return false, false
	}

	return *account.AuthorizedKeys == 0, true
}

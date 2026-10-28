package opacc1

import (
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV08Input struct {
	Deleted []history.Account

	IdentityProblem catalog.Message

	RetentionDays int
	Declared      map[string]time.Time
	UIDMin        int

	ConfigProblem catalog.Message
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if !in.ConfigProblem.IsZero() {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if !in.IdentityProblem.IsZero() {
		return notEvaluable(verdict.CauseCollection, in.IdentityProblem)
	}

	checked := 0
	var violations []catalog.Message
	var unknown []string

	for _, account := range in.Deleted {

		if account.UID < in.UIDMin || account.DeletedAt == nil {
			continue
		}

		if account.DisabledSince == nil && account.StateUnknown {
			unknown = append(unknown, account.AccountName)
			continue
		}

		if account.DisabledSince == nil {
			checked++
			violations = append(violations, catalog.Says("opacc1.ev08.deleted_enabled", "account", account.AccountName))
			continue
		}

		start, known := retentionStart(account, in.Declared)

		if !known {
			unknown = append(unknown, account.AccountName)
			continue
		}

		checked++

		days := int(account.DeletedAt.UTC().Truncate(24*time.Hour).Sub(start.UTC().Truncate(24*time.Hour)).Hours() / 24)

		if days < in.RetentionDays {
			violations = append(violations, catalog.Says("opacc1.account_days", "account", account.AccountName, "days", days))
		}
	}

	if len(violations) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc1.ev08.early", "days", in.RetentionDays, "accounts", violations))
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence, catalog.Says("opacc1.ev08.unknown", "accounts", unknown))
	}

	if checked == 0 {
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev08.none"))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc1.ev08.kept", "accounts", checked, "days", in.RetentionDays))
}

func retentionStart(account history.Account, declared map[string]time.Time) (time.Time, bool) {

	if date, ok := declared[account.AccountName]; ok {
		return date, true
	}

	if account.AccountExpires != "" {
		if date, err := time.Parse("2006-01-02", account.AccountExpires); err == nil {
			return date, true
		}
	}

	if account.DisabledObserved {
		return *account.DisabledSince, true
	}

	return time.Time{}, false
}

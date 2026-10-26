package opacc1

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

type EV08Input struct {
	Deleted []history.Account

	IdentityProblem string

	RetentionDays int
	Declared      map[string]time.Time
	UIDMin        int

	ConfigProblem string
}

func JudgeEV08(in EV08Input) verdict.Judgement {

	if in.ConfigProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	if in.IdentityProblem != "" {
		return notEvaluable(verdict.CauseCollection, "identity table: "+in.IdentityProblem)
	}

	checked := 0
	var violations, unknown []string

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
			violations = append(violations, account.AccountName+" (deleted while enabled)")
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
			violations = append(violations, fmt.Sprintf("%s (%d days)", account.AccountName, days))
		}
	}

	if len(violations) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: fmt.Sprintf("deleted before %d days (P-06): %s", in.RetentionDays, strings.Join(violations, ", ")),
		}
	}

	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence,
			"deleted accounts with no known offboarding date or state, retention cannot be measured: "+strings.Join(unknown, ", "))
	}

	if checked == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no account deleted in the window"}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts deleted in the window, all kept at least %d days (P-06)", checked, in.RetentionDays),
	}
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

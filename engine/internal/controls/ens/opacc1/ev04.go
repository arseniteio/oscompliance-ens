package opacc1

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// DefaultUIDMin is the product default for P-10, the same value v1 applied.
const DefaultUIDMin = 1000

// EV04Input is what the engine knows about one agent when judging EV-04.
type EV04Input struct {
	// Accounts are the identity_record facts of the newest complete EV-02
	// pass. AccountsProblem says why there is none; "" when there is.
	Accounts        []fact.IdentityRecord
	AccountsProblem string

	// Declared is P-09: offboarding date by account name. DeclaredSet is
	// false when P-09 has no rows.
	Declared    map[string]time.Time
	DeclaredSet bool

	// DeadlineDays is P-05. UIDMin is P-10 (DefaultUIDMin when not set).
	DeadlineDays int
	UIDMin       int

	// ConfigProblem names an unusable P-05, P-09 or P-10; "" when usable.
	ConfigProblem string

	// Now is the evaluation time: days are counted up to it.
	Now time.Time
}

// JudgeEV04 judges EV-04 (accounts of people who left are disabled within the
// deadline) as described in catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. P-05, P-09 or P-10 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. No complete identity pass: NOT_EVALUABLE, COLLECTION.
//  3. For each account with UID >= P-10 and an offboarding date (its P-09
//     row, else its account_expires), still enabled more than P-05 days
//     after that date: NON_COMPLIANT.
//  4. No offboarding date anywhere (P-09 empty, no account expiry): nothing
//     can be measured, NOT_EVALUABLE, CONFIGURATION.
//  5. Otherwise COMPLIANT.
func JudgeEV04(in EV04Input) verdict.Judgement {

	// 1. Without the deadline or with unreadable dates nothing is measured.
	if in.ConfigProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	// 2. The identity table says which accounts are still enabled.
	if in.AccountsProblem != "" {
		return notEvaluable(verdict.CauseCollection, "identity table: "+in.AccountsProblem)
	}

	today := in.Now.UTC().Truncate(24 * time.Hour)

	measured := 0
	var overdue []string

	for _, account := range in.Accounts {

		if account.UID < in.UIDMin {
			continue
		}

		left, known := offboardingDate(account, in.Declared)

		if !known {
			continue
		}

		measured++

		if IsDisabled(account, today) {
			continue
		}

		days := int(today.Sub(left.UTC().Truncate(24*time.Hour)).Hours() / 24)

		if days > in.DeadlineDays {
			overdue = append(overdue, fmt.Sprintf("%s (%d days)", account.AccountName, days))
		}
	}

	// 3. Enabled after the deadline.
	if len(overdue) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: fmt.Sprintf("enabled more than %d days (P-05) after leaving: %s", in.DeadlineDays, strings.Join(overdue, ", ")),
		}
	}

	// 4. No date to measure against, and nobody declared there are none.
	if measured == 0 && !in.DeclaredSet {
		return notEvaluable(verdict.CauseConfiguration, "no offboarding dates: P-09 is empty and no account has an expiry date")
	}

	// 5. Every known offboarding is disabled or still within the deadline.
	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts with an offboarding date, none enabled past %d days (P-05)", measured, in.DeadlineDays),
	}
}

// offboardingDate is the P-09 date of the account, else its expiry date, as
// v1 did.
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

// IsDisabled follows v1: no-login shell, locked password, or expired account.
// Exported for the EV-08 history, which must agree with EV-04.
func IsDisabled(account fact.IdentityRecord, today time.Time) bool {

	if strings.HasSuffix(account.Shell, "/nologin") || strings.HasSuffix(account.Shell, "/false") {
		return true
	}

	if account.PasswordState == fact.PasswordLocked {
		return true
	}

	if account.AccountExpires == "" {
		return false
	}

	expires, err := time.Parse("2006-01-02", account.AccountExpires)

	return err == nil && !expires.After(today)
}

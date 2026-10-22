package opacc1

import (
	"fmt"
	"strings"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/history"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// EV08Input is what the engine knows about one agent when judging EV-08.
type EV08Input struct {
	// Deleted are the history entries of accounts deleted in the window.
	Deleted []history.Account

	// IdentityProblem says why there is no complete current identity pass,
	// without which deletions cannot be seen; "" when there is one.
	IdentityProblem string

	// RetentionDays is P-06. Declared is P-09 (offboarding date by name).
	// UIDMin is P-10.
	RetentionDays int
	Declared      map[string]time.Time
	UIDMin        int

	// ConfigProblem names an unusable P-06, P-09 or P-10; "" when usable.
	ConfigProblem string
}

// JudgeEV08 judges EV-08 (disabled accounts are kept P-06 days before being
// deleted) as described in catalog/docs/contracts/op.acc.1.md, section 7:
//
//  1. P-06, P-09 or P-10 unusable: NOT_EVALUABLE, CONFIGURATION.
//  2. No complete current identity pass: NOT_EVALUABLE, COLLECTION.
//  3. An account with UID >= P-10, deleted in the window less than P-06
//     days after its offboarding date, or deleted while still enabled (kept
//     zero days): NON_COMPLIANT.
//  4. A deleted account whose start date is unknown: NOT_EVALUABLE, EVIDENCE.
//  5. Otherwise COMPLIANT.
func JudgeEV08(in EV08Input) verdict.Judgement {

	// 1. Without the retention period nothing is measured.
	if in.ConfigProblem != "" {
		return notEvaluable(verdict.CauseConfiguration, in.ConfigProblem)
	}

	// 2. Deletions are seen by comparing passes: without a current one, a
	// deletion in the window could be missing.
	if in.IdentityProblem != "" {
		return notEvaluable(verdict.CauseCollection, "identity table: "+in.IdentityProblem)
	}

	checked := 0
	var violations, unknown []string

	for _, account := range in.Deleted {

		if account.UID < in.UIDMin || account.DeletedAt == nil {
			continue
		}

		// Last seen in an unknown state: whether it was disabled is not known.
		if account.DisabledSince == nil && account.StateUnknown {
			unknown = append(unknown, account.AccountName)
			continue
		}

		// Deleted without being disabled first: kept zero days. v1 did not
		// track these accounts at all.
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

	// 3. Deleted too early.
	if len(violations) > 0 {
		return verdict.Judgement{
			Status: verdict.NonCompliant,
			Reason: fmt.Sprintf("deleted before %d days (P-06): %s", in.RetentionDays, strings.Join(violations, ", ")),
		}
	}

	// 4. Deleted, but since when was it out of use is not known.
	if len(unknown) > 0 {
		return notEvaluable(verdict.CauseEvidence,
			"deleted accounts with no known offboarding date or state, retention cannot be measured: "+strings.Join(unknown, ", "))
	}

	// 5. Nothing deleted too early.
	if checked == 0 {
		return verdict.Judgement{Status: verdict.Compliant, Reason: "no account deleted in the window"}
	}

	return verdict.Judgement{
		Status: verdict.Compliant,
		Reason: fmt.Sprintf("%d accounts deleted in the window, all kept at least %d days (P-06)", checked, in.RetentionDays),
	}
}

// retentionStart is the offboarding date (P-09, else the last expiry seen) or,
// when the engine saw the account being disabled, that date. v1 knew only the
// first two and called the rest unknown.
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

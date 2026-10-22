// Package history keeps, per agent and account, what the engine has seen of
// the account across identity passes (EV-02): when it was first and last
// present, since when it is disabled and when it disappeared. EV-08 needs it
// to measure retention over P-06 days, longer than any window of facts. It
// lives on the server, so the agent stays stateless.
package history

import (
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// Account is one document of the history index.
type Account struct {
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	AccountName string `json:"account_name"`
	UID         int    `json:"uid"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastRunID string    `json:"last_run_id"`

	// AccountExpires is the last account_expires seen, kept because the
	// record is gone once the account is deleted.
	AccountExpires string `json:"account_expires,omitempty"`

	// DisabledSince is the first pass of the current disabled run; nil while
	// the account is enabled. DisabledObserved: the engine saw it enabled
	// before, so DisabledSince is a measured date and not only a lower bound.
	DisabledSince    *time.Time `json:"disabled_since,omitempty"`
	DisabledObserved bool       `json:"disabled_observed"`

	// DeletedAt is the first pass where the account was missing; nil while
	// it exists.
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// DisabledFunc says whether an account is disabled at a given day.
type DisabledFunc func(fact.IdentityRecord, time.Time) bool

// Update applies one complete identity pass taken at "at" to the known
// history of one agent and returns the accounts that changed, new ones
// included. Applying the same pass twice changes nothing the second time.
func Update(known map[string]Account, agentID, agentName string, records []fact.IdentityRecord, at time.Time, runID string, disabled DisabledFunc) []Account {

	at = at.UTC()
	day := at.Truncate(24 * time.Hour)

	var changed []Account
	present := map[string]bool{}

	for _, record := range records {

		if present[record.AccountName] {
			continue // a repeated name: the first record wins, as in EV-02
		}
		present[record.AccountName] = true

		before, existed := known[record.AccountName]
		after := before

		if !existed {
			after = Account{AgentID: agentID, AccountName: record.AccountName, FirstSeen: at}
		}

		after.AgentName = agentName
		after.UID = record.UID
		after.AccountExpires = record.AccountExpires
		after.DeletedAt = nil

		if at.After(after.LastSeen) {
			after.LastSeen = at
			after.LastRunID = runID
		}

		if disabled(record, day) {
			if after.DisabledSince == nil {
				since := at
				after.DisabledSince = &since
				// Seen enabled before: the change itself was observed.
				after.DisabledObserved = existed
			}
		} else {
			after.DisabledSince = nil
			after.DisabledObserved = false
		}

		if !existed || !same(before, after) {
			changed = append(changed, after)
		}
	}

	for name, account := range known {

		if present[name] || account.DeletedAt != nil {
			continue
		}

		deleted := at
		account.DeletedAt = &deleted
		changed = append(changed, account)
	}

	return changed
}

func same(a, b Account) bool {
	return a.AgentName == b.AgentName && a.UID == b.UID && a.AccountExpires == b.AccountExpires &&
		a.LastSeen.Equal(b.LastSeen) && a.LastRunID == b.LastRunID &&
		equalTime(a.DisabledSince, b.DisabledSince) && a.DisabledObserved == b.DisabledObserved &&
		equalTime(a.DeletedAt, b.DeletedAt)
}

func equalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

package history

import (
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

type Account struct {
	AgentID     string `json:"agent_id"`
	AgentName   string `json:"agent_name"`
	AccountName string `json:"account_name"`
	UID         int    `json:"uid"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastRunID string    `json:"last_run_id"`

	AccountExpires string `json:"account_expires,omitempty"`

	DisabledSince    *time.Time `json:"disabled_since,omitempty"`
	DisabledObserved bool       `json:"disabled_observed"`

	StateUnknown bool `json:"state_unknown"`

	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

type DisabledFunc func(fact.IdentityRecord, time.Time) (disabled, known bool)

func Update(known map[string]Account, agentID, agentName string, records []fact.IdentityRecord, at time.Time, runID string, disabled DisabledFunc) []Account {

	at = at.UTC()
	day := at.Truncate(24 * time.Hour)

	var changed []Account
	present := map[string]bool{}

	for _, record := range records {

		if present[record.AccountName] {
			continue
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

		isDisabled, known := disabled(record, day)

		switch {
		case !known:

			after.StateUnknown = true
		case isDisabled:
			after.StateUnknown = false
			if after.DisabledSince == nil {
				since := at
				after.DisabledSince = &since

				after.DisabledObserved = existed && !before.StateUnknown
			}
		default:
			after.StateUnknown = false
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
		a.StateUnknown == b.StateUnknown &&
		equalTime(a.DeletedAt, b.DeletedAt)
}

func equalTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

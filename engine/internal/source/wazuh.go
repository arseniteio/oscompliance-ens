package source

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// Facts that Wazuh produces by itself, from its own decoders and rules. The
// agent does nothing for them; the engine reads the alerts as they are.

// authGroups are the rule groups that prove an agent's authentication log
// reaches Wazuh: v1 probed its log for the same three kinds of line.
var authGroups = []any{"authentication_success", "authentication_failed", "sudo"}

// Login methods.
const (
	MethodSSHD      = "sshd"
	MethodConsole   = "console"
	MethodSU        = "su"
	MethodGraphical = "graphical"
)

// pamPrograms are the PAM services whose opened session is an interactive
// login, by method. sshd is taken from its own rule (5715) instead, so it is
// not counted twice; sudo is privilege use, not a login; cron and systemd
// sessions are not people.
var pamPrograms = map[string]string{
	"login":        MethodConsole,
	"su":           MethodSU,
	"gdm-password": MethodGraphical,
	"lightdm":      MethodGraphical,
	"sddm":         MethodGraphical,
}

// Login is one successful interactive login as Wazuh decoded it.
type Login struct {
	Time     time.Time
	Account  string // data.dstuser: the account logged in as
	SourceIP string // data.srcip, sshd only
	// SourceUser is data.srcuser: who became Account (su).
	SourceUser string
	Method     string // one of the Method* values
	// Auth is how sshd authenticated it (publickey, password,
	// keyboard-interactive/pam...), "" for the other methods. With
	// AuthenticationMethods, the methods before it are in "Partial" lines.
	Auth    string
	KeyType string // the key type for publickey (ED25519, ECDSA-SK...)
	AlertID string // the alert's id, for traceability
}

// accepted reads the method and key type of an sshd "Accepted" line.
var accepted = regexp.MustCompile(`Accepted (\S+) for .* ssh2(?:: (\S+))?`)

// Logins returns the interactive logins of one agent since the given time,
// oldest first: sshd logins (rule 5715 and children) and PAM sessions opened
// by login, su and graphical login managers (rule 5501).
func (s *Source) Logins(ctx context.Context, agentID string, since time.Time) ([]Login, error) {

	var programs []any
	for program := range pamPrograms {
		programs = append(programs, program)
	}

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"rule.groups": "authentication_success"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{
			"minimum_should_match": 1,
			"should": []any{
				map[string]any{"term": map[string]any{"decoder.parent": "sshd"}},
				map[string]any{"bool": map[string]any{"filter": []any{
					map[string]any{"term": map[string]any{"decoder.parent": "pam"}},
					map[string]any{"terms": map[string]any{"predecoder.program_name": programs}},
				}}},
			},
		}},
	}

	var logins []Login

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			ID         string `json:"id"`
			Timestamp  string `json:"timestamp"`
			Predecoder struct {
				ProgramName string `json:"program_name"`
			} `json:"predecoder"`
			Decoder struct {
				Parent string `json:"parent"`
			} `json:"decoder"`
			Data struct {
				DstUser string `json:"dstuser"`
				SrcUser string `json:"srcuser"`
				SrcIP   string `json:"srcip"`
			} `json:"data"`
			FullLog string `json:"full_log"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		// Wazuh writes "2026-10-22T11:40:01.123+0000": no colon in the offset.
		ts, err := time.Parse("2006-01-02T15:04:05.000-0700", a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: timestamp: %w", h.ID, err)
		}

		method := MethodSSHD
		if a.Decoder.Parent == "pam" {
			method = pamPrograms[a.Predecoder.ProgramName]
		}

		login := Login{Time: ts, Account: a.Data.DstUser, SourceUser: a.Data.SrcUser, SourceIP: a.Data.SrcIP, Method: method, AlertID: a.ID}
		if m := accepted.FindStringSubmatch(a.FullLog); method == MethodSSHD && m != nil {
			login.Auth, login.KeyType = m[1], m[2]
		}

		logins = append(logins, login)
		return nil
	})

	return logins, err
}

// AuthActivity returns, per agent ID, the time of the newest authentication
// event (success, failure or sudo) since the given time. An agent missing from
// the map sent none: its authentication log is not reaching Wazuh, or nobody
// ever authenticated on it, and silence cannot be read as compliance.
func (s *Source) AuthActivity(ctx context.Context, since time.Time) (map[string]time.Time, error) {

	query := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"terms": map[string]any{"rule.groups": authGroups}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		}}},
		"aggs": map[string]any{"agents": map[string]any{
			"terms": map[string]any{"field": "agent.id", "size": maxAgents},
			"aggs":  map[string]any{"newest": map[string]any{"max": map[string]any{"field": "timestamp"}}},
		}},
	}

	var resp struct {
		Aggregations struct {
			Agents struct {
				Buckets []struct {
					Key    string `json:"key"`
					Newest struct {
						Value float64 `json:"value"` // epoch milliseconds
					} `json:"newest"`
				} `json:"buckets"`
			} `json:"agents"`
		} `json:"aggregations"`
	}

	if err := s.client.Search(ctx, s.index, query, &resp); err != nil {
		return nil, err
	}

	activity := map[string]time.Time{}

	for _, b := range resp.Aggregations.Agents.Buckets {
		activity[b.Key] = time.UnixMilli(int64(b.Newest.Value)).UTC()
	}

	return activity, nil
}

// ProbeRule is the Wazuh rule of the agent's authentication log probe
// (catalog/wazuh).
const ProbeRule = "119002"

var probeMarker = regexp.MustCompile(`auth log probe ([0-9a-f-]{36})`)

// ProbesSeen returns, per agent ID, the run IDs of the authentication log
// probes that came back as alerts since the given time.
func (s *Source) ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"rule.id": ProbeRule}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	seen := map[string]map[string]bool{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Agent struct {
				ID string `json:"id"`
			} `json:"agent"`
			FullLog string `json:"full_log"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		m := probeMarker.FindStringSubmatch(a.FullLog)
		if m == nil {
			return nil
		}

		if seen[a.Agent.ID] == nil {
			seen[a.Agent.ID] = map[string]bool{}
		}
		seen[a.Agent.ID][m[1]] = true
		return nil
	})

	return seen, err
}

// AuthLogProbes returns, per agent, up to n auth_log_probe facts since the
// given time, newest first.
func (s *Source) AuthLogProbes(ctx context.Context, since time.Time, n int) (map[string][]fact.AuthLogProbe, error) {
	return latestFacts[fact.AuthLogProbe](ctx, s, fact.AuthLogProbeFact, since, n)
}

// Failure is one failed authentication against an account that exists, as
// Wazuh decoded it: sshd (5760, 5716...), PAM (5503), su. Attempts against
// names that do not exist (group invalid_login) are left out.
type Failure struct {
	Time     time.Time
	Account  string
	SourceIP string
	Rule     string
}

// Failures returns the failed authentications of one agent since the given
// time, oldest first.
func (s *Source) Failures(ctx context.Context, agentID string, since time.Time) ([]Failure, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"rule.groups": "authentication_failed"}},
		map[string]any{"exists": map[string]any{"field": "data.dstuser"}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{"must_not": []any{
			map[string]any{"term": map[string]any{"rule.groups": "invalid_login"}},
		}}},
	}

	var failures []Failure

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Rule      struct {
				ID string `json:"id"`
			} `json:"rule"`
			Data struct {
				DstUser string `json:"dstuser"`
				SrcIP   string `json:"srcip"`
			} `json:"data"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		failures = append(failures, Failure{Time: ts, Account: a.Data.DstUser, SourceIP: a.Data.SrcIP, Rule: a.Rule.ID})
		return nil
	})

	return failures, err
}

// Lockout is an account locked after failed attempts, from the lines of
// pam_faillock and pam_tally2 (Wazuh has no decoder for them: they come as
// generic authentication failures, the account only in full_log).
type Lockout struct {
	Time    time.Time
	Account string
}

var lockoutLine = regexp.MustCompile(`pam_faillock\(\S+\): Consecutive login failures for user (\S+) account temporarily locked|pam_tally2\(\S+\): user (\S+) \(\d+\) tally \d+, deny \d+`)

// Lockouts returns the lockouts of one agent since the given time.
func (s *Source) Lockouts(ctx context.Context, agentID string, since time.Time) ([]Lockout, error) {

	filter := []any{
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{
			"minimum_should_match": 1,
			"should": []any{
				map[string]any{"match_phrase": map[string]any{"full_log": "account temporarily locked"}},
				map[string]any{"match_phrase": map[string]any{"full_log": "pam_tally2"}},
			},
		}},
	}

	var lockouts []Lockout

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			FullLog   string `json:"full_log"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		m := lockoutLine.FindStringSubmatch(a.FullLog)
		if m == nil {
			return nil
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		account := m[1]
		if account == "" {
			account = m[2]
		}

		lockouts = append(lockouts, Lockout{Time: ts, Account: account})
		return nil
	})

	return lockouts, err
}

// alertTime parses the alert timestamp Wazuh writes, "2026-10-22T11:40:01.123+0000".
func alertTime(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000-0700", s)
}

// ListeningSnapshots returns, per agent, the newest listening_snapshot.
func (s *Source) ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error) {
	return newest[fact.ListeningSnapshot](ctx, s, fact.ListeningSnapshotFact, since)
}

// ListeningSockets returns every listening_socket of one read of one agent.
func (s *Source) ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error) {
	return passRecords[fact.ListeningSocket](ctx, s, fact.ListeningSocketFact, agentID, runID, since)
}

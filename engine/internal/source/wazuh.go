package source

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/batch"
)

var authGroups = []any{"authentication_success", "authentication_failed", "sudo"}

const (
	MethodSSHD      = "sshd"
	MethodConsole   = "console"
	MethodSU        = "su"
	MethodGraphical = "graphical"
	MethodRDP       = "rdp"
)

func Remote(method string) bool {
	return method == MethodSSHD || method == MethodRDP
}

// Logon types 2 and 11 are interactive and cached interactive, 10 is Remote
// Desktop. Type 3 (network, WinRM, SMB) and 5 (service) are not logins of a
// person and would mark every service account as one.
var windowsLogonTypes = map[string]string{"2": MethodConsole, "11": MethodConsole, "10": MethodRDP}

const (
	eventLogon   = "4624"
	eventFailure = "4625"
	eventLockout = "4740"
)

type winEventData struct {
	TargetUserName   string `json:"targetUserName"`
	TargetDomainName string `json:"targetDomainName"`
	SubjectUserName  string `json:"subjectUserName"`
	IPAddress        string `json:"ipAddress"`
	LogonType        string `json:"logonType"`
	AuthPackage      string `json:"authenticationPackageName"`
}

type winAlert struct {
	System struct {
		EventID string `json:"eventID"`
	} `json:"system"`
	EventData winEventData `json:"eventdata"`
}

var windowsServiceAccounts = []string{"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"}

// windowsAccount leaves out computer accounts (HOST$) and the accounts of
// the operating system, which no person uses to log in.
func windowsAccount(name string) bool {
	return name != "" && name != "-" && !strings.HasSuffix(name, "$") &&
		!slices.ContainsFunc(windowsServiceAccounts, func(s string) bool { return strings.EqualFold(s, name) })
}

func windowsIP(ip string) string {
	if ip == "-" || ip == "::1" || ip == "127.0.0.1" {
		return ""
	}
	return ip
}

var pamPrograms = map[string]string{
	"login":        MethodConsole,
	"su":           MethodSU,
	"gdm-password": MethodGraphical,
	"lightdm":      MethodGraphical,
	"sddm":         MethodGraphical,
}

type Login struct {
	Time     time.Time
	Account  string
	SourceIP string

	SourceUser string
	Method     string

	Auth    string
	KeyType string
	AlertID string
}

var accepted = regexp.MustCompile(`Accepted (\S+) for .* ssh2(?:: (\S+))?`)

func (s *Source) Logins(ctx context.Context, agentID string, since time.Time) ([]Login, error) {
	return batched(ctx, s, "logins|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]Login, error) {
		return s.logins(ctx, ids, since)
	})
}

func (s *Source) logins(ctx context.Context, ids []string, since time.Time) (map[string][]Login, error) {

	var programs []any
	for program := range pamPrograms {
		programs = append(programs, program)
	}
	var logonTypes []any
	for t := range windowsLogonTypes {
		logonTypes = append(logonTypes, t)
	}

	success := map[string]any{"term": map[string]any{"rule.groups": "authentication_success"}}
	filter := []any{
		agentFilter(ids),
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{
			"minimum_should_match": 1,
			"should": []any{
				map[string]any{"bool": map[string]any{"filter": []any{success, map[string]any{"term": map[string]any{"decoder.parent": "sshd"}}}}},
				map[string]any{"bool": map[string]any{"filter": []any{
					success,
					map[string]any{"term": map[string]any{"decoder.parent": "pam"}},
					map[string]any{"terms": map[string]any{"predecoder.program_name": programs}},
				}}},
				map[string]any{"bool": map[string]any{"filter": []any{
					map[string]any{"term": map[string]any{"data.win.system.eventID": eventLogon}},
					map[string]any{"terms": map[string]any{"data.win.eventdata.logonType": logonTypes}},
				}}},
			},
		}},
	}

	logins := map[string][]Login{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			ID    string `json:"id"`
			Agent struct {
				ID string `json:"id"`
			} `json:"agent"`
			Timestamp  string `json:"timestamp"`
			Predecoder struct {
				ProgramName string `json:"program_name"`
			} `json:"predecoder"`
			Decoder struct {
				Parent string `json:"parent"`
			} `json:"decoder"`
			Data struct {
				DstUser string   `json:"dstuser"`
				SrcUser string   `json:"srcuser"`
				SrcIP   string   `json:"srcip"`
				Win     winAlert `json:"win"`
			} `json:"data"`
			FullLog string `json:"full_log"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := time.Parse("2006-01-02T15:04:05.000-0700", a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: timestamp: %w", h.ID, err)
		}

		if w := a.Data.Win; w.System.EventID == eventLogon {
			d := w.EventData
			if method, ok := windowsLogonTypes[d.LogonType]; ok && windowsAccount(d.TargetUserName) {
				logins[a.Agent.ID] = append(logins[a.Agent.ID], Login{Time: ts, Account: d.TargetUserName, SourceIP: windowsIP(d.IPAddress), Method: method, Auth: d.AuthPackage, AlertID: a.ID})
			}
			return nil
		}

		method := MethodSSHD
		if a.Decoder.Parent == "pam" {
			method = pamPrograms[a.Predecoder.ProgramName]
		}

		login := Login{Time: ts, Account: a.Data.DstUser, SourceUser: a.Data.SrcUser, SourceIP: a.Data.SrcIP, Method: method, AlertID: a.ID}
		if m := accepted.FindStringSubmatch(a.FullLog); method == MethodSSHD && m != nil {
			login.Auth, login.KeyType = m[1], m[2]
		}

		logins[a.Agent.ID] = append(logins[a.Agent.ID], login)
		return nil
	})

	return logins, err
}

func (s *Source) AuthActivity(ctx context.Context, since time.Time) (map[string]time.Time, error) {

	filter := []any{
		map[string]any{"terms": map[string]any{"rule.groups": authGroups}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
	}

	activity := map[string]time.Time{}

	err := s.composite(ctx, filter, []any{map[string]any{"a": map[string]any{"terms": map[string]any{"field": "agent.id"}}}}, lastSeen,
		func(key map[string]any, b json.RawMessage) error {
			_, last, err := countAndLast(b)
			activity[keyString(key, "a")] = last
			return err
		})

	return activity, err
}

const ProbeRule = "119002"

var probeMarker = regexp.MustCompile(`auth log probe ([0-9a-f-]{36})`)

func (s *Source) ProbesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error) {
	seen, err := batch.Once(ctx, &s.pass.plan, "probes|"+sinceKey(since), func(ctx context.Context) (map[string]map[string]bool, error) {
		return s.probesSeen(ctx, since)
	})
	return maps.Clone(seen), err
}

func (s *Source) probesSeen(ctx context.Context, since time.Time) (map[string]map[string]bool, error) {

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

func (s *Source) AuthLogProbes(ctx context.Context, since time.Time, n int) (map[string][]fact.AuthLogProbe, error) {
	return latestFacts[fact.AuthLogProbe](ctx, s, fact.AuthLogProbeFact, since, n)
}

type Failure struct {
	Time     time.Time
	Account  string
	SourceIP string
	Rule     string
}

func (s *Source) Failures(ctx context.Context, agentID string, since time.Time) ([]Failure, error) {
	return batched(ctx, s, "failures|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]Failure, error) {
		return s.failures(ctx, ids, since)
	})
}

func (s *Source) failures(ctx context.Context, ids []string, since time.Time) (map[string][]Failure, error) {

	filter := []any{
		agentFilter(ids),
		map[string]any{"term": map[string]any{"rule.groups": "authentication_failed"}},
		map[string]any{"bool": map[string]any{"minimum_should_match": 1, "should": []any{
			map[string]any{"exists": map[string]any{"field": "data.dstuser"}},
			map[string]any{"term": map[string]any{"data.win.system.eventID": eventFailure}},
		}}},
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{"must_not": []any{
			map[string]any{"term": map[string]any{"rule.groups": "invalid_login"}},
		}}},
	}

	failures := map[string][]Failure{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Agent     struct {
				ID string `json:"id"`
			} `json:"agent"`
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
			Data struct {
				DstUser string   `json:"dstuser"`
				SrcIP   string   `json:"srcip"`
				Win     winAlert `json:"win"`
			} `json:"data"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		account, ip := a.Data.DstUser, a.Data.SrcIP
		if w := a.Data.Win; w.System.EventID == eventFailure {
			account, ip = w.EventData.TargetUserName, windowsIP(w.EventData.IPAddress)
			if !windowsAccount(account) {
				return nil
			}
		}
		if account == "" {
			return nil
		}

		failures[a.Agent.ID] = append(failures[a.Agent.ID], Failure{Time: ts, Account: account, SourceIP: ip, Rule: a.Rule.ID})
		return nil
	})

	return failures, err
}

type Lockout struct {
	Time    time.Time
	Account string
}

var lockoutLine = regexp.MustCompile(`pam_faillock\(\S+\): Consecutive login failures for user (\S+) account temporarily locked|pam_tally2\(\S+\): user (\S+) \(\d+\) tally \d+, deny \d+`)

func (s *Source) Lockouts(ctx context.Context, agentID string, since time.Time) ([]Lockout, error) {
	return batched(ctx, s, "lockouts|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string][]Lockout, error) {
		return s.lockouts(ctx, ids, since)
	})
}

func (s *Source) lockouts(ctx context.Context, ids []string, since time.Time) (map[string][]Lockout, error) {

	filter := []any{
		agentFilter(ids),
		map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": since.UTC().Format(time.RFC3339)}}},
		map[string]any{"bool": map[string]any{
			"minimum_should_match": 1,
			"should": []any{
				map[string]any{"match_phrase": map[string]any{"full_log": "account temporarily locked"}},
				map[string]any{"match_phrase": map[string]any{"full_log": "pam_tally2"}},
				map[string]any{"term": map[string]any{"data.win.system.eventID": eventLockout}},
			},
		}},
	}

	lockouts := map[string][]Lockout{}

	err := s.page(ctx, filter, func(h hit) error {

		var a struct {
			Timestamp string `json:"timestamp"`
			Agent     struct {
				ID string `json:"id"`
			} `json:"agent"`
			FullLog string `json:"full_log"`
			Data    struct {
				Win winAlert `json:"win"`
			} `json:"data"`
		}

		if err := json.Unmarshal(h.Source, &a); err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		ts, err := alertTime(a.Timestamp)
		if err != nil {
			return fmt.Errorf("alert %s: %w", h.ID, err)
		}

		var account string
		if w := a.Data.Win; w.System.EventID == eventLockout {
			account = w.EventData.TargetUserName
			if !windowsAccount(account) {
				return nil
			}
		} else if m := lockoutLine.FindStringSubmatch(a.FullLog); m != nil {
			account = m[1]
			if account == "" {
				account = m[2]
			}
		}
		if account == "" {
			return nil
		}

		lockouts[a.Agent.ID] = append(lockouts[a.Agent.ID], Lockout{Time: ts, Account: account})
		return nil
	})

	return lockouts, err
}

func alertTime(s string) (time.Time, error) {
	return time.Parse("2006-01-02T15:04:05.000-0700", s)
}

func (s *Source) ListeningSnapshots(ctx context.Context, since time.Time) (map[string]fact.ListeningSnapshot, error) {
	return newest[fact.ListeningSnapshot](ctx, s, fact.ListeningSnapshotFact, since)
}

func (s *Source) ListeningSockets(ctx context.Context, agentID, runID string, since time.Time) ([]fact.ListeningSocket, error) {
	return passRecords[fact.ListeningSocket](ctx, s, fact.ListeningSocketFact, agentID, runID, since)
}

package source

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Manager is the state of the Wazuh manager the engine reads through its API: what runs, the rules it
// loads and how it responds and notifies.
type Manager struct {
	Daemons       map[string]string
	Rules         []Rule
	RuleExclude   []string
	Responses     []Response
	Email         Email
	Integrations  []Integration
	Vulnerability bool
	Version       string
	Installed     time.Time
}

type Rule struct {
	ID         int
	Level      int
	File       string
	Dir        string
	Groups     []string
	Mitre      []string
	Frequency  int
	Correlates bool
}

// Custom rules live in etc/rules; the rest ship with Wazuh.
func (r Rule) Custom() bool { return r.Dir == "etc/rules" }

type Response struct {
	Command  string
	Rules    string
	Groups   string
	Level    string
	Location string
	Disabled bool
}

type Email struct {
	Enabled bool
	To      []string
	Level   int
}

type Integration struct {
	Name   string
	Level  int
	Groups string
}

var ErrNoManagerAPI = errors.New("the engine has no Wazuh API to read the manager (-wazuh-api)")

type managerCache struct {
	mu    sync.Mutex
	read  func(ctx context.Context) (*Manager, error)
	at    time.Time
	value *Manager
	err   error
}

// The manager is read once for every control of a pass.
const managerFresh = 5 * time.Minute

// UseManager sets how the manager is read.
func (s *Source) UseManager(read func(ctx context.Context) (*Manager, error)) {
	s.manager.read = read
}

func (s *Source) Manager(ctx context.Context) (*Manager, error) {

	c := &s.manager
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.read == nil {
		return nil, ErrNoManagerAPI
	}
	if time.Since(c.at) < managerFresh {
		return c.value, c.err
	}
	c.value, c.err = c.read(ctx)
	c.at = time.Now()
	return c.value, c.err
}

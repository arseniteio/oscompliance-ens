package fact

import (
	"crypto/rand"
	"fmt"
)

const EnvelopeVersion = "1"

type Envelope struct {
	OSCompliance string `json:"oscompliance"`
	Fact         string `json:"fact"`
	TS           string `json:"ts"`
	Host         string `json:"host"`
	AgentVersion string `json:"agent_version"`
	RunID        string `json:"run_id"`

	RecordsRunID string `json:"records_run_id,omitempty"`
}

func (e Envelope) RecordsRun() string {
	if e.RecordsRunID != "" {
		return e.RecordsRunID
	}
	return e.RunID
}

func (e *Envelope) Seen(ts string) {
	e.TS = ts
}

func NewRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

const (
	SourceRead        = "read"
	SourceUnreadable  = "unreadable"
	SourceImplausible = "implausible"
)

const AgentPassFact = "agent_pass"

type AgentPass struct {
	Envelope
	InForce []string `json:"in_force"`
}

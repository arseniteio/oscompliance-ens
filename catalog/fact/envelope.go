// Package fact defines the wire format of facts: the envelope shared by every
// fact and the payload types. Schemas: catalog/schemas/facts.
package fact

import (
	"crypto/rand"
	"fmt"
)

// EnvelopeVersion is the value of the "oscompliance" field.
const EnvelopeVersion = "1"

// Envelope holds the fields every fact line carries. Payload types embed it so
// encoding/json writes envelope and payload at the same level.
type Envelope struct {
	OSCompliance string `json:"oscompliance"`
	Fact         string `json:"fact"`
	TS           string `json:"ts"`
	Host         string `json:"host"`
	AgentVersion string `json:"agent_version"`
	RunID        string `json:"run_id"`
	// RecordsRunID: on a snapshot, the earlier pass whose records still hold.
	RecordsRunID string `json:"records_run_id,omitempty"`
}

// RecordsRun is the pass whose records belong to this snapshot: its own,
// or the earlier one it points to when nothing changed.
func (e Envelope) RecordsRun() string {
	if e.RecordsRunID != "" {
		return e.RecordsRunID
	}
	return e.RunID
}

// Seen moves the observation time of a snapshot to a later pass that found
// it unchanged (AgentPass).
func (e *Envelope) Seen(ts string) {
	e.TS = ts
}

// NewRunID returns a random UUID v4 identifying one collection pass.
func NewRunID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// Values of the *_status field of every snapshot fact.
const (
	SourceRead        = "read"
	SourceUnreadable  = "unreadable"
	SourceImplausible = "implausible"
)

// AgentPassFact closes every pass of the agent.
const AgentPassFact = "agent_pass"

// AgentPass names, for every quiet collector of the pass, the snapshot that
// holds now as "fact:run_id": the one sent in this pass, or an earlier one
// the collector did not send again because nothing changed.
type AgentPass struct {
	Envelope
	InForce []string `json:"in_force"`
}

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

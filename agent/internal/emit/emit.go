// Package emit writes facts as NDJSON lines to the file the Wazuh agent reads.
package emit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fact"
)

// Emitter stamps envelopes for one collection pass and writes one fact per line.
type Emitter struct {
	w            io.Writer
	host         string
	agentVersion string
	runID        string
	now          func() time.Time
}

// New returns an Emitter for one pass. All facts it stamps share runID.
func New(w io.Writer, host, agentVersion, runID string) *Emitter {
	return &Emitter{w: w, host: host, agentVersion: agentVersion, runID: runID, now: time.Now}
}

// Envelope returns the envelope for a fact of the given name, stamped now.
func (e *Emitter) Envelope(name string) fact.Envelope {
	return fact.Envelope{
		OSCompliance: fact.EnvelopeVersion,
		Fact:         name,
		TS:           e.now().UTC().Format(time.RFC3339),
		Host:         e.host,
		AgentVersion: e.agentVersion,
		RunID:        e.runID,
	}
}

// Emit writes v as one JSON line. The line goes out in a single Write call so
// that, with an O_APPEND file, concurrent writers never interleave lines.
func (e *Emitter) Emit(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("emit: marshal: %w", err)
	}
	if _, err := e.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("emit: write: %w", err)
	}
	return nil
}

// OpenFile opens path for appending, creating it with mode 0640.
func OpenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
}

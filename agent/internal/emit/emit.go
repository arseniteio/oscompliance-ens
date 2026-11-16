package emit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

type Emitter struct {
	w            io.Writer
	host         string
	agentVersion string
	runID        string
	now          func() time.Time
}

func New(w io.Writer, host, agentVersion, runID string) *Emitter {
	return &Emitter{w: w, host: host, agentVersion: agentVersion, runID: runID, now: time.Now}
}

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

func (e *Emitter) Emit(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("emit: marshal: %w", err)
	}
	// One Write per line: appends to an O_APPEND file never interleave.
	if _, err := e.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("emit: write: %w", err)
	}
	return nil
}

func OpenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
}

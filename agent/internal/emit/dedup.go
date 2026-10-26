package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/fsread"
	"os"
	"path/filepath"
	"time"
)

// The agent emits a collector's records only when they change, and once a
// day anyway: an unchanged pass sends its snapshot alone, pointing with
// records_run_id to the pass that carried the records. On a large fleet
// this cuts the facts sent by an order of magnitude; the snapshots still
// prove every hour that the machine was looked at.

// FullEvery is how often records go out even when nothing changed. It is
// shorter than the engine's window, so the records a snapshot points to are
// always within reach.
const FullEvery = 23 * time.Hour

// State is the only thing the agent remembers between passes: per
// collector, a hash of the records last emitted and the pass that carried
// them. Losing it only costs one full emission.
type State struct {
	path       string
	Collectors map[string]Sent `json:"collectors"`
}

// Sent is what one collector last emitted in full.
type Sent struct {
	Hash  string    `json:"hash"`
	RunID string    `json:"run_id"`
	At    time.Time `json:"at"`
}

// LoadState reads the state file. A missing or damaged file is an empty
// state: everything goes out in full.
func LoadState(path string) *State {

	s := &State{path: path, Collectors: map[string]Sent{}}

	data, err := fsread.ReadFile(path)
	if err != nil {
		return s
	}

	var loaded State
	if json.Unmarshal(data, &loaded) == nil && loaded.Collectors != nil {
		s.Collectors = loaded.Collectors
	}

	return s
}

// Save writes the state atomically, readable by root only.
func (s *State) Save() error {

	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}

	return os.Rename(tmp, s.path)
}

// Reduce takes the lines one collector emitted in one pass, records first
// and its snapshot last, and returns what to write: everything, or the
// snapshot alone when the records are those already sent. commit records
// what was sent; call it only after the lines are written.
func (s *State) Reduce(collector string, lines []byte, now time.Time, full bool) (out []byte, commit func(), err error) {

	all := bytes.Split(bytes.TrimSuffix(lines, []byte("\n")), []byte("\n"))

	// A collector with no records (one fact) has nothing to spare.
	if len(all) < 2 {
		return lines, func() {}, nil
	}

	records, snapshot := all[:len(all)-1], all[len(all)-1]

	hash, err := recordsHash(records)
	if err != nil {
		return nil, nil, err
	}

	var head struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(snapshot, &head); err != nil {
		return nil, nil, err
	}

	last, known := s.Collectors[collector]

	if !full && known && last.Hash == hash && last.RunID != "" && now.Sub(last.At) < FullEvery {
		pointed, err := withRecordsRun(snapshot, last.RunID)
		if err != nil {
			return nil, nil, err
		}
		return append(pointed, '\n'), func() {}, nil
	}

	commit = func() { s.Collectors[collector] = Sent{Hash: hash, RunID: head.RunID, At: now} }
	return lines, commit, nil
}

// recordsHash hashes the records without what changes every pass: the
// observation time and the pass id.
func recordsHash(records [][]byte) (string, error) {

	h := sha256.New()

	for _, r := range records {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			return "", err
		}
		delete(m, "ts")
		delete(m, "run_id")

		// encoding/json writes map keys sorted: the same record gives the
		// same bytes.
		b, err := json.Marshal(m)
		if err != nil {
			return "", err
		}
		h.Write(b)
		h.Write([]byte{'\n'})
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// withRecordsRun adds records_run_id to a snapshot line, keeping its order
// of fields except that one at the end.
func withRecordsRun(snapshot []byte, runID string) ([]byte, error) {

	if !bytes.HasSuffix(snapshot, []byte("}")) {
		return nil, errors.New("snapshot is not a JSON object")
	}

	field, _ := json.Marshal(runID)
	out := append([]byte{}, snapshot[:len(snapshot)-1]...)
	out = append(out, []byte(`,"records_run_id":`)...)
	out = append(out, field...)
	return append(out, '}'), nil
}

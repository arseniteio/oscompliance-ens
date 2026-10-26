package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/fsread"
	"os"
	"path/filepath"
	"time"
)

// The agent emits a collector's records only when they change: an
// unchanged pass sends its snapshot alone, pointing with records_run_id to
// the pass that carried the records. A quiet collector sends nothing at all
// when its snapshot did not change either: the agent_pass fact that closes
// every pass names the snapshot still in force (fact.AgentPass). Everything
// goes out in full every FullEvery anyway. On a large fleet this cuts the
// facts sent by an order of magnitude.

// FullEvery is how often records and snapshots go out even when nothing
// changed: what is lost on the way comes back within that time. The engine
// looks for what is in force further back than that (source.reach).
const FullEvery = 3 * 24 * time.Hour

// State is the only thing the agent remembers between passes: per
// collector, a hash of the records last emitted and the pass that carried
// them. Losing it only costs one full emission.
type State struct {
	path       string
	Collectors map[string]Sent `json:"collectors"`
}

// Sent is what one collector last emitted.
type Sent struct {
	// Hash, RunID and At: the records last sent in full, the pass that
	// carried them and when.
	Hash  string    `json:"hash"`
	RunID string    `json:"run_id"`
	At    time.Time `json:"at"`
	// The snapshot last sent: its fact, its pass and a hash of its content.
	Snapshot     string `json:"snapshot,omitempty"`
	SnapshotRun  string `json:"snapshot_run,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
}

// InForce returns the snapshot of collector that still holds, as
// "fact:run_id" (fact.AgentPass), or "" when none was sent.
func (s *State) InForce(collector string) string {
	c := s.Collectors[collector]
	if c.Snapshot == "" || c.SnapshotRun == "" {
		return ""
	}
	return c.Snapshot + ":" + c.SnapshotRun
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
// and its snapshot last, and returns what to write: everything; the
// snapshot alone when the records are those already sent; nothing, for a
// quiet collector, when the snapshot is also the one already sent. commit
// records what was sent; call it only after the lines are written.
func (s *State) Reduce(collector string, lines []byte, now time.Time, full, quiet bool) (out []byte, commit func(), err error) {

	all := bytes.Split(bytes.TrimSuffix(lines, []byte("\n")), []byte("\n"))

	// A collector with no records (one fact) has nothing to spare unless it
	// is quiet.
	if len(all) < 2 && !quiet {
		return lines, func() {}, nil
	}

	records, snapshot := all[:len(all)-1], all[len(all)-1]

	hash, err := recordsHash(records)
	if err != nil {
		return nil, nil, err
	}
	snapshotHash, err := recordsHash([][]byte{snapshot})
	if err != nil {
		return nil, nil, err
	}

	var head struct {
		Fact  string `json:"fact"`
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(snapshot, &head); err != nil {
		return nil, nil, err
	}

	last, known := s.Collectors[collector]

	// A clock that went backwards proves nothing about the age: send in full.
	recent := !full && known && last.Hash == hash && last.RunID != "" && !now.Before(last.At) && now.Sub(last.At) < FullEvery

	sentSnapshot := func(c Sent) Sent {
		c.Snapshot, c.SnapshotRun, c.SnapshotHash = head.Fact, head.RunID, snapshotHash
		return c
	}

	switch {
	case recent && quiet && last.Snapshot == head.Fact && last.SnapshotRun != "" && last.SnapshotHash == snapshotHash:
		return nil, func() {}, nil

	case recent:
		out := append([]byte{}, snapshot...)
		if len(records) > 0 {
			if out, err = withRecordsRun(snapshot, last.RunID); err != nil {
				return nil, nil, err
			}
		}
		return append(out, '\n'), func() { s.Collectors[collector] = sentSnapshot(last) }, nil
	}

	commit = func() { s.Collectors[collector] = sentSnapshot(Sent{Hash: hash, RunID: head.RunID, At: now}) }
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

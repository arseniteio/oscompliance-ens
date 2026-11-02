package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"os"
	"path/filepath"
	"time"
)

const FullEvery = 3 * 24 * time.Hour

type State struct {
	path       string
	Collectors map[string]Sent `json:"collectors"`
}

type Sent struct {
	Hash  string    `json:"hash"`
	RunID string    `json:"run_id"`
	At    time.Time `json:"at"`

	Snapshot     string `json:"snapshot,omitempty"`
	SnapshotRun  string `json:"snapshot_run,omitempty"`
	SnapshotHash string `json:"snapshot_hash,omitempty"`
}

func (s *State) InForce(collector string) string {
	c := s.Collectors[collector]
	if c.Snapshot == "" || c.SnapshotRun == "" {
		return ""
	}
	return c.Snapshot + ":" + c.SnapshotRun
}

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

func (s *State) Reduce(collector string, lines []byte, now time.Time, full, quiet bool) (out []byte, commit func(), err error) {

	all := bytes.Split(bytes.TrimSuffix(lines, []byte("\n")), []byte("\n"))

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

func recordsHash(records [][]byte) (string, error) {

	h := sha256.New()

	for _, r := range records {
		var m map[string]any
		if err := json.Unmarshal(r, &m); err != nil {
			return "", err
		}
		delete(m, "ts")
		delete(m, "run_id")

		b, err := json.Marshal(m)
		if err != nil {
			return "", err
		}
		h.Write(b)
		h.Write([]byte{'\n'})
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

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

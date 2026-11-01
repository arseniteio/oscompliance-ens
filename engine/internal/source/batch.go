package source

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/batch"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type passState struct {
	plan   batch.Plan
	mu     sync.Mutex
	wanted map[string]map[string]map[string]bool
}

func (s *Source) Plan(agents []verdict.Agent) {

	ids := make([]string, len(agents))
	for i, a := range agents {
		ids[i] = a.ID
	}
	s.pass.plan.Set(ids)

	s.pass.mu.Lock()
	s.pass.wanted = map[string]map[string]map[string]bool{}
	s.pass.mu.Unlock()
}

func batched[R any](ctx context.Context, s *Source, key, agentID string, fetch func(ctx context.Context, ids []string) (map[string]R, error)) (R, error) {
	return batch.Get(ctx, &s.pass.plan, key, agentID, fetch)
}

func agentFilter(ids []string) any {
	return termFilter("agent.id", ids...)
}

func sinceKey(t time.Time) string {
	return fmt.Sprint(t.UnixMilli())
}

var recordsOf = map[string]string{
	fact.IdentitySnapshotFact:   fact.IdentityRecordFact,
	fact.GroupSnapshotFact:      fact.GroupRecordFact,
	fact.SudoersSnapshotFact:    fact.SudoGrantFact,
	fact.ConfigSnapshotFact:     fact.ConfigFileFact,
	fact.PAMSnapshotFact:        fact.PAMRuleFact,
	fact.ListeningSnapshotFact:  fact.ListeningSocketFact,
	fact.ServiceLogSnapshotFact: fact.ServiceLogFact,
	fact.FileSweepSnapshotFact:  fact.SpecialFileFact,
	fact.ACLSnapshotFact:        fact.ACLRecordFact,
}

func (s *Source) want(snapshot, agentID string, v any) {

	name, ok := recordsOf[snapshot]
	if !ok {
		return
	}
	r, ok := v.(interface{ RecordsRun() string })
	if !ok || r.RecordsRun() == "" {
		return
	}

	s.pass.mu.Lock()
	defer s.pass.mu.Unlock()

	if s.pass.wanted == nil {
		s.pass.wanted = map[string]map[string]map[string]bool{}
	}
	if s.pass.wanted[name] == nil {
		s.pass.wanted[name] = map[string]map[string]bool{}
	}
	if s.pass.wanted[name][agentID] == nil {
		s.pass.wanted[name][agentID] = map[string]bool{}
	}
	s.pass.wanted[name][agentID][r.RecordsRun()] = true
}

type recordRuns[T any] struct {
	read    map[string]bool
	records map[string][]T
}

func passRecords[T any](ctx context.Context, s *Source, name, agentID, runID string, since time.Time) ([]T, error) {

	since = since.Add(-reach)

	runs, err := batched(ctx, s, "records|"+name+"|"+sinceKey(since), agentID, func(ctx context.Context, ids []string) (map[string]recordRuns[T], error) {
		return chunkRecords[T](ctx, s, name, ids, since)
	})
	if err != nil {
		return nil, err
	}

	if runs.read[runID] {
		return runs.records[runID], nil
	}

	filter := append(factFilter(name, since),
		map[string]any{"term": map[string]any{"agent.id": agentID}},
		map[string]any{"term": map[string]any{"data.run_id": runID}},
	)

	var records []T

	err = s.page(ctx, filter, func(h hit) error {
		var record T
		if _, err := decodeAlert(h, &record); err != nil {
			return err
		}
		records = append(records, record)
		return nil
	})

	return records, err
}

func chunkRecords[T any](ctx context.Context, s *Source, name string, ids []string, since time.Time) (map[string]recordRuns[T], error) {

	out := map[string]recordRuns[T]{}
	var runs []string

	s.pass.mu.Lock()
	for _, id := range ids {
		r := recordRuns[T]{read: map[string]bool{}, records: map[string][]T{}}
		for run := range s.pass.wanted[name][id] {
			r.read[run] = true
			runs = append(runs, run)
		}
		out[id] = r
	}
	s.pass.mu.Unlock()

	if len(runs) == 0 {
		return out, nil
	}

	filter := append(factFilter(name, since), agentFilter(ids), termFilter("data.run_id", runs...))

	err := s.page(ctx, filter, func(h hit) error {
		var record T
		a, err := decodeAlert(h, &record)
		if err != nil {
			return err
		}
		run, _ := a.Data["run_id"].(string)
		if r, ok := out[a.Agent.ID]; ok && r.read[run] {
			r.records[run] = append(r.records[run], record)
		}
		return nil
	})

	return out, err
}

func decodeAlert(h hit, v any) (alert, error) {

	var a alert

	if err := json.Unmarshal(h.Source, &a); err != nil {
		return a, fmt.Errorf("alert %s: %w", h.ID, err)
	}

	if err := Decode(a.Data, v); err != nil {
		return a, fmt.Errorf("alert %s: %w", h.ID, err)
	}

	return a, nil
}

package winupdate

import (
	_ "embed"
	"maps"
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed update.ps1
var script string

const (
	Manager = "windows-update"
	actor   = "Windows Update"

	operationUninstall = 2
)

type entry struct {
	Date      string `json:"date"`
	Title     string `json:"title"`
	Operation int    `json:"operation"`
}

type output struct {
	LastSearch  string  `json:"last_search"`
	Pending     int     `json:"pending"`
	Security    int     `json:"security"`
	SearchError string  `json:"search_error"`
	History     []entry `json:"history"`
}

func read(run winps.Runner) (output, error) {
	return winps.Decode[output](run, script)
}

func CollectStatus(e *emit.Emitter, run winps.Runner) error {

	s := fact.UpdateStatus{Envelope: e.Envelope(fact.UpdateStatusFact), Manager: Manager, Status: fact.SourceRead}

	out, err := read(run)
	switch {
	case err != nil:
		s.Status, s.Error = fact.SourceError, err.Error()
	case out.SearchError != "":
		s.Status, s.Error = fact.SourceError, out.SearchError
	default:
		s.ListsUpdated = normalise(out.LastSearch)
		s.Pending, s.Security = out.Pending, out.Security
	}
	return e.Emit(s)
}

// CollectTransactions emits one transaction per installation time: Windows Update installs a batch under one timestamp.
func CollectTransactions(e *emit.Emitter, run winps.Runner) error {

	s := fact.TransactionSnapshot{Envelope: e.Envelope(fact.TransactionSnapshotFact), Manager: Manager, Status: fact.SourceRead}

	out, err := read(run)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	byStart := map[string]*fact.PackageTransaction{}
	for _, h := range out.History {
		start := normalise(h.Date)
		if start == "" {
			continue
		}
		t, ok := byStart[start]
		if !ok {
			t = &fact.PackageTransaction{Envelope: e.Envelope(fact.PackageTransactionFact), Start: start, End: start, Actor: actor}
			byStart[start] = t
		}
		if h.Operation == operationUninstall {
			t.Removed = append(t.Removed, h.Title)
		} else {
			t.Installed = append(t.Installed, h.Title)
		}
	}

	for _, start := range slices.Sorted(maps.Keys(byStart)) {
		if err := e.Emit(*byStart[start]); err != nil {
			return err
		}
		s.RecordsEmitted++
	}
	return e.Emit(s)
}

func normalise(iso string) string {
	t, err := time.Parse(time.RFC3339Nano, iso)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

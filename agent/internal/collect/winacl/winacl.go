package winacl

import (
	_ "embed"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/wazuh"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/winaudit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed acl.ps1
var script string

type record struct {
	Path   string   `json:"path"`
	Status string   `json:"status"`
	Error  string   `json:"error"`
	Owner  string   `json:"owner"`
	ACL    []string `json:"acl"`
}

func Collect(e *emit.Emitter, run winps.Runner, paths wazuh.AgentConfigPaths) error {

	s := fact.ACLSnapshot{Envelope: e.Envelope(fact.ACLSnapshotFact), Config: paths.SharedConf, Status: fact.SourceRead}

	shared, ok, err := wazuh.ReadSharedPaths(paths)
	switch {
	case err != nil:
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	case !ok:
		s.Status = fact.SourceAbsent
		return e.Emit(s)
	}

	var wanted []string
	for _, p := range shared.ACLPaths {
		if winaudit.Absolute(p) {
			wanted = append(wanted, p)
		}
	}
	if len(wanted) == 0 {
		return e.Emit(s)
	}

	input, err := winps.WithInput(map[string][]string{"paths": wanted}, script)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}
	out, err := winps.Decode[struct {
		Records []record `json:"records"`
	}](run, input)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	for _, r := range out.Records {
		if err := e.Emit(fact.ACLRecord{Envelope: e.Envelope(fact.ACLRecordFact), Path: r.Path, Status: r.Status, Error: r.Error, Owner: r.Owner, ACL: r.ACL}); err != nil {
			return err
		}
		s.RecordsEmitted++
	}
	return e.Emit(s)
}

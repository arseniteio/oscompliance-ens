// Package scope tells which machines a control is measured on when the regulation asks it of only some of
// them: a measure the organisation must have somewhere is measured where it is, and when it is nowhere the
// manager carries the failure for the organisation instead of every machine being left out.
package scope

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
)

// Machines answers, for one pass, which machines the configuration lets the engine judge.
type Machines struct {
	config    *params.Config
	reporting map[string]source.Reporting
}

func MachinesOf(config *params.Config, reporting map[string]source.Reporting) Machines {
	return Machines{config: config, reporting: reporting}
}

func (m Machines) Evaluable(agentID string) bool {
	return m.config.Evaluates(agentID, m.reporting[agentID].Groups)
}

func (m Machines) Excluded(controlID, agentID string) bool {
	return m.config.Excludes(controlID, m.reporting[agentID].Groups)
}

// Fleet are the machines of a pass: their ids by name, the manager included.
type Fleet struct {
	ids map[string]string
}

func FleetOf(reporting map[string]source.Reporting) Fleet {
	f := Fleet{ids: map[string]string{}}
	for id, r := range reporting {
		f.ids[strings.ToLower(r.Name)] = id
	}
	return f
}

// Has tells whether a machine of that name reports to Wazuh.
func (f Fleet) Has(name string) bool {
	_, ok := f.ids[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// ID is the agent id of a machine by name.
func (f Fleet) ID(name string) (string, bool) {
	id, ok := f.ids[strings.ToLower(strings.TrimSpace(name))]
	return id, ok
}

// IDs are the agent ids of the fleet, the manager among them.
func (f Fleet) IDs() []string {
	out := []string{source.ManagerID}
	for _, id := range f.ids {
		if id != source.ManagerID {
			out = append(out, id)
		}
	}
	return out
}

// Any tells whether some machine of the fleet passes a test.
func (f Fleet) Any(test func(id string) bool) bool {
	for _, id := range f.IDs() {
		if test(id) {
			return true
		}
	}
	return false
}

// Carrier is the machine that carries the evidences of a measure the organisation has nowhere.
func Carrier(agentID string) bool { return agentID == source.ManagerID }

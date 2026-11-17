package winservices

import (
	_ "embed"
	"slices"
	"strconv"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed services.ps1
var script string

type service struct {
	Name  string `json:"name"`
	State string `json:"state"`
	Start string `json:"start"`
	Exit  int    `json:"exit"`
	PID   int    `json:"pid"`
}

type process struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type socket struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	PID      int    `json:"pid"`
}

type output struct {
	Services  []service          `json:"services"`
	Processes map[string]process `json:"processes"`
	Sockets   []socket           `json:"sockets"`
	Addresses []string           `json:"addresses"`
}

func CollectUnits(e *emit.Emitter, run winps.Runner) error {

	s := fact.UnitSnapshot{Envelope: e.Envelope(fact.UnitSnapshotFact), Status: fact.SourceRead, Units: []string{}, Failed: []string{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceError, err.Error()
		return e.Emit(s)
	}

	for _, svc := range out.Services {
		running := strings.EqualFold(svc.State, "Running")
		if running {
			s.Units = append(s.Units, svc.Name)
		}
		// A stopped automatic service with exit code 0 ended on purpose, as trigger-start services do.
		if !running && strings.EqualFold(svc.Start, "Auto") && svc.Exit != 0 {
			s.Failed = append(s.Failed, svc.Name)
		}
	}
	slices.Sort(s.Units)
	slices.Sort(s.Failed)
	return e.Emit(s)
}

func CollectListening(e *emit.Emitter, run winps.Runner) error {

	s := fact.ListeningSnapshot{Envelope: e.Envelope(fact.ListeningSnapshotFact), Status: fact.SourceRead, Addresses: []string{}, ProcessesMatched: true}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}
	if out.Addresses != nil {
		s.Addresses = out.Addresses
	}

	byPID := map[int][]service{}
	for _, svc := range out.Services {
		if svc.PID > 0 {
			byPID[svc.PID] = append(byPID[svc.PID], svc)
		}
	}

	seen := map[string]bool{}
	for _, sock := range out.Sockets {
		key := sock.Protocol + "|" + sock.Address + "|" + strconv.Itoa(sock.Port)
		if seen[key] {
			continue
		}
		seen[key] = true

		r := fact.ListeningSocket{Envelope: e.Envelope(fact.ListeningSocketFact), Protocol: sock.Protocol, Address: sock.Address, Port: sock.Port, PID: sock.PID}
		if p, ok := out.Processes[strconv.Itoa(sock.PID)]; ok {
			r.Process, r.Exe = p.Name, p.Path
		}
		if hosted := byPID[sock.PID]; len(hosted) > 0 {
			slices.SortFunc(hosted, func(a, b service) int { return strings.Compare(a.Name, b.Name) })
			r.Unit, r.UnitEnabled = hosted[0].Name, startMode(hosted[0].Start)
		}
		if err := e.Emit(r); err != nil {
			return err
		}
		s.RecordsEmitted++
	}
	return e.Emit(s)
}

func startMode(mode string) string {
	switch strings.ToLower(mode) {
	case "auto", "boot", "system":
		return "enabled"
	case "manual":
		return "manual"
	}
	return "disabled"
}

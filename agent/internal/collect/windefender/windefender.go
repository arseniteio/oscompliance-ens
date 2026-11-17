package windefender

import (
	_ "embed"
	"os"
	"slices"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

//go:embed defender.ps1
var script string

const Product = "windows-defender"

// SignatureScheduleDay 8 is "never"; a positive interval updates every that many hours.
const neverScheduled = 8

type output struct {
	Installed       bool   `json:"installed"`
	Running         bool   `json:"running"`
	Version         string `json:"version"`
	RealTime        bool   `json:"realtime"`
	Signatures      string `json:"signatures"`
	ScheduleDay     *int   `json:"signature_schedule_day"`
	Interval        *int   `json:"signature_interval"`
	ArchiveScanning bool   `json:"archive_scanning"`
	LastScan        string `json:"last_scan"`
	AppLocker       string `json:"applocker"`
}

type Config struct {
	Responses string
}

var Default = Config{Responses: `C:\Program Files (x86)\ossec-agent\active-response\bin`}

func Collect(e *emit.Emitter, run winps.Runner, cfg Config) error {

	s := fact.MalwareProtection{Envelope: e.Envelope(fact.MalwareProtectionFact), Status: fact.SourceRead, Allowlist: "absent", Products: []fact.Antimalware{}, Settings: []string{}, Responses: []string{}}

	out, err := winps.Decode[output](run, script)
	if err != nil {
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	if out.Installed {
		s.Products = append(s.Products, fact.Antimalware{Product: Product, Running: out.Running, Version: out.Version})
		s.Signatures, s.LastScan = out.Signatures, out.LastScan
		s.Settings = settings(out)
	}
	s.Allowlist = out.AppLocker

	if entries, err := os.ReadDir(cfg.Responses); err == nil {
		for _, en := range entries {
			if !en.IsDir() {
				s.Responses = append(s.Responses, en.Name())
			}
		}
	}

	return e.Emit(s)
}

func settings(out output) []string {
	var on []string
	if out.RealTime {
		on = append(on, "proteccion_tiempo_real")
	}
	if (out.ScheduleDay != nil && *out.ScheduleDay != neverScheduled) || (out.Interval != nil && *out.Interval > 0) {
		on = append(on, "actualizacion_automatica_firmas")
	}
	if out.ArchiveScanning {
		on = append(on, "analisis_comprimidos")
	}
	// Defender writes every detection to its own event channel, which the Windows group agent.conf forwards.
	on = append(on, "registro_syslog")
	return slices.Clip(on)
}

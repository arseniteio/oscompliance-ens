package passes

import (
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
)

const probeDelivery = 10 * time.Minute

type AuthLog struct {
	Known   bool
	Reaches bool

	Detail catalog.Message
}

func ProbeResult(probes []fact.AuthLogProbe, seen map[string]bool, now time.Time) AuthLog {

	written, settled, lastError := 0, 0, ""

	for _, p := range probes {

		if p.Status != fact.ProbeWritten {
			lastError = p.Error
			continue
		}
		written++

		if seen[p.RunID] {
			return AuthLog{Known: true, Reaches: true, Detail: catalog.Says("probe.back", "run", p.RunID, "ts", p.TS)}
		}

		if ts, err := time.Parse(time.RFC3339, p.TS); err == nil && now.Sub(ts) > probeDelivery {
			settled++
		}
	}

	switch {
	case len(probes) == 0:
		return AuthLog{Detail: catalog.Says("gap.no_fact", "fact", "auth_log_probe")}
	case written == 0:
		return AuthLog{Detail: catalog.Says("probe.not_written", "error", lastError)}
	case settled == 0:
		return AuthLog{Detail: catalog.Says("probe.pending")}
	}

	return AuthLog{Known: true, Detail: catalog.Says("probe.lost", "count", settled)}
}

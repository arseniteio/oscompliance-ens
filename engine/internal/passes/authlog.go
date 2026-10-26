package passes

import (
	"fmt"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// probeDelivery is how long a probe may take to come back as an alert: the
// Wazuh agent reads the log every few seconds, the manager and the indexer
// take a few more.
const probeDelivery = 10 * time.Minute

// AuthLog says whether the machine's authentication log reaches Wazuh.
type AuthLog struct {
	Known   bool
	Reaches bool
	// Detail says why it is not known, or what was checked.
	Detail string
}

// ProbeResult reads the agent's probes in the window against the probe
// alerts that came back. One probe seen is enough; probes written long
// enough ago that never came back mean the log does not reach Wazuh.
func ProbeResult(probes []fact.AuthLogProbe, seen map[string]bool, now time.Time) AuthLog {

	written, settled, lastError := 0, 0, ""

	for _, p := range probes {

		if p.Status != fact.ProbeWritten {
			lastError = p.Error
			continue
		}
		written++

		if seen[p.RunID] {
			return AuthLog{Known: true, Reaches: true, Detail: "probe " + p.RunID + " of " + p.TS + " came back from Wazuh"}
		}

		if ts, err := time.Parse(time.RFC3339, p.TS); err == nil && now.Sub(ts) > probeDelivery {
			settled++
		}
	}

	switch {
	case len(probes) == 0:
		return AuthLog{Detail: "no auth_log_probe in the window"}
	case written == 0:
		return AuthLog{Detail: "the agent could not write its probe to syslog: " + lastError}
	case settled == 0:
		return AuthLog{Detail: "the newest probe has not had time to come back yet"}
	}

	return AuthLog{Known: true, Detail: fmt.Sprintf("%d probes written to the authentication log never reached Wazuh", settled)}
}

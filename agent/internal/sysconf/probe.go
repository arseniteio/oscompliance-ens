package sysconf

import (
	"log/syslog"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-core/catalog/fact"
)

// ProbeTag is the syslog tag of the probe line; Wazuh rule 119002 matches it.
const ProbeTag = "oscompliance-agent"

// CollectAuthProbe writes "auth log probe <run_id>" to the authpriv facility,
// where sshd, PAM and sudo write, and emits an auth_log_probe saying whether
// it could. The engine looks for the line among the alerts: when it comes
// back, the authentication log reaches Wazuh even on a machine nobody logs
// in to.
func CollectAuthProbe(e *emit.Emitter) error {

	probe := fact.AuthLogProbe{Envelope: e.Envelope(fact.AuthLogProbeFact), Status: fact.ProbeWritten}

	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_INFO, ProbeTag)

	if err == nil {
		err = w.Info("auth log probe " + probe.RunID)
		w.Close()
	}

	if err != nil {
		probe.Status, probe.Error = fact.ProbeError, err.Error()
	}

	return e.Emit(probe)
}

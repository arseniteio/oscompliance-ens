package authprobe

import (
	"log/syslog"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

const ProbeTag = "oscompliance-agent"

func Collect(e *emit.Emitter) error {

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

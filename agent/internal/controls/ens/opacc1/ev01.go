// Package opacc1 collects the facts of ENS control op.acc.1.
package opacc1

import (
	"errors"

	"github.com/OpenSourceCompliance/oscompliance-core/agent/internal/emit"
)

// EV01Config holds the agent-side parameters of EV-01 (contract section 6).
type EV01Config struct {
	PasswdPath string
	UIDMin     int
}

// CollectEV01 reads the account database and emits one account_record per
// account with UID >= UIDMin, then one account_inventory_snapshot. The
// snapshot is emitted even when the source cannot be read.
func CollectEV01(e *emit.Emitter, cfg EV01Config) error {
	// TODO(dioni): read cfg.PasswdPath and emit the EV-01 facts.
	return errors.New("opacc1: EV-01 not implemented")
}

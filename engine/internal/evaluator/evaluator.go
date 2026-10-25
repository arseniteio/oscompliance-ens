// Package evaluator is the contract between the run loop and each control:
// a control reads its facts once per pass and judges its evidences for each
// agent. Applicability, writing and aggregation are the run loop's.
package evaluator

import (
	"context"
	"time"

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/verdict"
)

// Pass is the time frame of one evaluation pass.
type Pass struct {
	Now           time.Time
	WindowStart   time.Time // facts newer than this count for a verdict
	LookbackStart time.Time // history and agent activity reach back to this
}

// Result is one evidence judgement and the pass of facts it judged.
type Result struct {
	Judgement verdict.Judgement
	RunID     string
}

// Evaluator judges the evidences of one control.
type Evaluator interface {
	// Control is the catalog id, such as "op.acc.1".
	Control() string
	// Begin reads what the control needs for every agent, once per pass.
	Begin(ctx context.Context, pass Pass) error
	// Agent judges the evidences of one agent. An evidence missing from the
	// result (its facts could not be read) is a COLLECTION gap for the
	// requirements; the error says why.
	Agent(ctx context.Context, agent verdict.Agent, policy params.Lister) (map[string]Result, error)
}

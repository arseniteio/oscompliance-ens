// Package verdict defines what the engine writes to the verdicts index.
// Schema: catalog/schemas/verdicts.
package verdict

// Status is the result of judging one evidence on one agent.
type Status string

const (
	Compliant    Status = "COMPLIANT"
	NonCompliant Status = "NON_COMPLIANT"
	NotEvaluable Status = "NOT_EVALUABLE"
	// NotApplicable: the evidence does not apply at the active ENS level, or
	// the control is disabled in the configuration.
	NotApplicable Status = "NOT_APPLICABLE"
)

// Cause says why an evidence is NotEvaluable. Never set with another status.
type Cause string

const (
	// CauseCollection: the facts needed are missing, unreadable or incomplete.
	CauseCollection Cause = "COLLECTION"
	// CauseConfiguration: a parameter the judgement needs is not set.
	CauseConfiguration Cause = "CONFIGURATION"
	// CauseEvidence: the facts arrived but cannot be trusted.
	CauseEvidence Cause = "EVIDENCE"
)

// Judgement is what a control's judge function returns for one evidence.
type Judgement struct {
	Status Status
	Cause  Cause
	Reason string
}

// SchemaVersion is the value of the "oscompliance_verdict" field.
const SchemaVersion = "1"

// Verdict is one document of the verdicts index: a Judgement plus where and
// when it applies.
type Verdict struct {
	OSComplianceVerdict string `json:"oscompliance_verdict"`
	Timestamp           string `json:"@timestamp"`
	Control             string `json:"control"`
	Evidence            string `json:"evidence"`
	Agent               Agent  `json:"agent"`
	Status              Status `json:"status"`
	Cause               Cause  `json:"cause,omitempty"`
	Reason              string `json:"reason,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	WindowStart         string `json:"window_start"`
	WindowEnd           string `json:"window_end"`
	EngineVersion       string `json:"engine_version"`
}

// Agent identifies the Wazuh agent the facts came from.
type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

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
	// Partial: only for a control, some applicable requirements comply.
	Partial Status = "PARTIAL"
)

// Scopes of a verdict document.
const (
	ScopeEvidence    = "evidence"
	ScopeRequirement = "requirement"
	ScopeControl     = "control"
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
	Scope               string `json:"scope"`
	Control             string `json:"control"`
	Requirement         string `json:"requirement,omitempty"`
	Evidence            string `json:"evidence,omitempty"`
	Agent               Agent  `json:"agent"`
	Status              Status `json:"status"`
	Cause               Cause  `json:"cause,omitempty"`
	Reason              string `json:"reason,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	WindowStart         string `json:"window_start"`
	WindowEnd           string `json:"window_end"`
	EngineVersion       string `json:"engine_version"`

	// Requirement scope: Evidenced is false when the verdict comes from a
	// lack of proof, not a measure; Attested when a document proves it.
	Evidenced *bool `json:"evidenced,omitempty"`
	Attested  bool  `json:"attested,omitempty"`

	// Control scope.
	Score                  *int     `json:"score,omitempty"`
	Coverage               *int     `json:"coverage,omitempty"`
	ApplicableRequirements *int     `json:"applicable_requirements,omitempty"`
	MeasuredRequirements   *int     `json:"measured_requirements,omitempty"`
	UnmeasuredRequirements []string `json:"unmeasured_requirements,omitempty"`
}

// Agent identifies the Wazuh agent the facts came from.
type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

package verdict

type Status string

const (
	Compliant    Status = "COMPLIANT"
	NonCompliant Status = "NON_COMPLIANT"
	NotEvaluable Status = "NOT_EVALUABLE"

	NotApplicable Status = "NOT_APPLICABLE"

	Partial Status = "PARTIAL"
)

const (
	ScopeEvidence    = "evidence"
	ScopeRequirement = "requirement"
	ScopeControl     = "control"
)

type Cause string

const (
	CauseCollection Cause = "COLLECTION"

	CauseConfiguration Cause = "CONFIGURATION"

	CauseEvidence Cause = "EVIDENCE"
)

type Judgement struct {
	Status Status
	Cause  Cause
	Reason string
}

const SchemaVersion = "1"

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

	Evidenced *bool `json:"evidenced,omitempty"`
	Attested  bool  `json:"attested,omitempty"`

	Score                  *int     `json:"score,omitempty"`
	Coverage               *int     `json:"coverage,omitempty"`
	ApplicableRequirements *int     `json:"applicable_requirements,omitempty"`
	MeasuredRequirements   *int     `json:"measured_requirements,omitempty"`
	UnmeasuredRequirements []string `json:"unmeasured_requirements,omitempty"`
}

type Agent struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

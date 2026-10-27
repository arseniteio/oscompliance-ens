package fact

const (
	UmaskSnapshotFact = "umask_snapshot"
)

type UmaskSource struct {
	Path            string   `json:"path"`
	Status          string   `json:"status"`
	Error           string   `json:"error,omitempty"`
	Umasks          []string `json:"umasks,omitzero"`
	Uninterpretable []string `json:"uninterpretable,omitempty"`
}

type UmaskSnapshot struct {
	Envelope
	Sources []UmaskSource `json:"sources"`
}

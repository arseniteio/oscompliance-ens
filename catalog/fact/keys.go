package fact

const (
	KeyRecordFact         = "key_record"
	CertificateRecordFact = "certificate_record"
	KeySnapshotFact       = "key_snapshot"
)

type KeyRecord struct {
	Envelope
	Path        string `json:"path"`
	Kind        string `json:"key_kind"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Mode        string `json:"mode"`
	Owner       string `json:"owner"`
}

type CertificateRecord struct {
	Envelope
	Path      string `json:"path"`
	Subject   string `json:"subject"`
	NotAfter  string `json:"not_after"`
	KeyAlgo   string `json:"key_algorithm"`
	KeyBits   int    `json:"key_bits"`
	Signature string `json:"signature_algorithm"`
}

type KeySnapshot struct {
	Envelope
	Status       string   `json:"status"`
	Error        string   `json:"error,omitempty"`
	Roots        []string `json:"roots"`
	Truncated    bool     `json:"truncated,omitempty"`
	Keys         int      `json:"keys_emitted"`
	Certificates int      `json:"certificates_emitted"`
}

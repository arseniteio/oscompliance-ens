package fact

const (
	VirtualizationFact = "virtualization"
)

type Virtualization struct {
	Envelope
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Virtual  bool   `json:"virtual"`
	Platform string `json:"platform,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Product  string `json:"product,omitempty"`
	Source   string `json:"source,omitempty"`
}

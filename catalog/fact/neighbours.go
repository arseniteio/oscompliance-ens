package fact

const (
	NeighbourSnapshotFact = "neighbour_snapshot"
)

type Neighbour struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Interface string `json:"interface"`
}

type NeighbourSnapshot struct {
	Envelope
	Status     string      `json:"status"`
	Error      string      `json:"error,omitempty"`
	Neighbours []Neighbour `json:"neighbours"`
}

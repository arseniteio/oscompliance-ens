package catalog

import "encoding/json"

type DefaultScope struct {
	Mode     string   `json:"mode"`
	GroupIDs []string `json:"groupIds"`
}

type DefaultConfiguration struct {
	EnsLevel string       `json:"ensLevel"`
	Scope    DefaultScope `json:"scope"`
}

func Default() DefaultConfiguration {

	raw, err := files.ReadFile("default-configuration.json")
	if err != nil {
		panic(err)
	}

	var d DefaultConfiguration
	if err := json.Unmarshal(raw, &d); err != nil {
		panic(err)
	}

	return d
}

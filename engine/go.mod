module github.com/arseniteio/oscompliance-ens-wazuh/engine

go 1.27.2

require (
	github.com/arseniteio/oscompliance-ens-wazuh/catalog v0.0.0
	go.yaml.in/yaml/v3 v3.0.6
)

// The catalog (fact types, controls, templates) lives in this repository.
replace github.com/arseniteio/oscompliance-ens-wazuh/catalog => ../catalog

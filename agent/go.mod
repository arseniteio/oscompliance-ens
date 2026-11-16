module github.com/arseniteio/oscompliance-ens-wazuh/agent

go 1.27.2

require github.com/arseniteio/oscompliance-ens-wazuh/catalog v0.0.0

// The catalog (fact types, controls, templates) lives in this repository.
replace github.com/arseniteio/oscompliance-ens-wazuh/catalog => ../catalog

module github.com/arseniteio/oscompliance-ens/engine

go 1.27.2

require github.com/arseniteio/oscompliance-ens/catalog v0.0.0

// The catalog (fact types, controls, templates) lives in this repository.
replace github.com/arseniteio/oscompliance-ens/catalog => ../catalog

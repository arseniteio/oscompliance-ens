module github.com/OpenSourceCompliance/oscompliance-core/engine

go 1.27.2

require github.com/OpenSourceCompliance/oscompliance-core/catalog v0.0.0

// The catalog (fact types, controls, templates) lives in this repository.
replace github.com/OpenSourceCompliance/oscompliance-core/catalog => ../catalog

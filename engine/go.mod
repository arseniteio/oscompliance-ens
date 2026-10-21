module github.com/OpenSourceCompliance/oscompliance-core/engine

go 1.27.2

require github.com/OpenSourceCompliance/oscompliance-core/catalog/fact v0.0.0

// The fact types live in this repository, next to the schemas they mirror.
replace github.com/OpenSourceCompliance/oscompliance-core/catalog/fact => ../catalog/fact

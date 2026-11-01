package main

import (
	"bytes"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func TestEveryCollectorIsWired(t *testing.T) {
	collectors := collectorsFor(emit.New(&bytes.Buffer{}, "h", "test", "run"), options{})
	for _, name := range allCollectors {
		if collectors[name] == nil {
			t.Errorf("collector %q has no function", name)
		}
	}
	if len(collectors) != len(allCollectors) {
		t.Errorf("%d functions for %d collectors", len(collectors), len(allCollectors))
	}
}

package main

import (
	"bytes"
	"encoding/json"
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

func TestAgentPassCarriesTheRequestedGroup(t *testing.T) {

	var buf, out bytes.Buffer
	e := emit.New(&buf, "h", "test", "6e8a0c2d-4f6b-4d8f-8b2c-4d6e8f0a2b3c")

	if err := writeAgentPass(&out, &buf, e, []string{"listening_snapshot:6e8a0c2d-4f6b-4d8f-8b2c-4d6e8f0a2b3c"}, "ens"); err != nil {
		t.Fatal(err)
	}

	var pass struct {
		RequestedGroup string `json:"requested_group"`
	}
	if err := json.Unmarshal(out.Bytes(), &pass); err != nil {
		t.Fatal(err)
	}
	if pass.RequestedGroup != "ens" {
		t.Errorf("requested_group = %q, want ens", pass.RequestedGroup)
	}
}

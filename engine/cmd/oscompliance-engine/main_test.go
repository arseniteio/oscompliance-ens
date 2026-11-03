package main

import (
	"context"
	"testing"

	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

type namedControl string

func (c namedControl) Control() string { return string(c) }

func (namedControl) Begin(context.Context, evaluator.Pass) error { return nil }

func (namedControl) Agent(context.Context, verdict.Agent, params.Lister) (map[string]evaluator.Result, error) {
	return nil, nil
}

func TestSelectControls(t *testing.T) {
	all := []evaluator.Evaluator{namedControl("op.acc.1"), namedControl("op.acc.2"), namedControl("op.exp.1")}

	tests := []struct {
		name, names string
		want        []string
		wantErr     bool
	}{
		{name: "empty keeps every control", names: "", want: []string{"op.acc.1", "op.acc.2", "op.exp.1"}},
		{name: "one control", names: "op.acc.1", want: []string{"op.acc.1"}},
		{name: "spaces are ignored", names: "op.acc.1, op.exp.1", want: []string{"op.acc.1", "op.exp.1"}},
		{name: "unknown control stops the engine", names: "op.acc.9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectControls(all, tt.names)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d controls, want %d", len(got), len(tt.want))
			}
			for i, ev := range got {
				if ev.Control() != tt.want[i] {
					t.Errorf("control %d = %s, want %s", i, ev.Control(), tt.want[i])
				}
			}
		})
	}
}

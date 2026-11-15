package groupconf

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/engine/internal/wazuhapi"
)

type fakeAssigner struct {
	members  map[string][]wazuhapi.Agent
	assigned map[string][]string
}

func (f *fakeAssigner) GroupAgents(_ context.Context, group string) ([]wazuhapi.Agent, error) {
	return f.members[group], nil
}

func (f *fakeAssigner) AssignAgents(_ context.Context, group string, ids []string) error {
	if f.assigned == nil {
		f.assigned = map[string][]string{}
	}
	f.assigned[group] = append(f.assigned[group], ids...)
	return nil
}

func TestAssignAddsOnlyAgentsThatAskForAScopeGroupAndAreOutsideIt(t *testing.T) {

	api := &fakeAssigner{members: map[string][]wazuhapi.Agent{"ens": {{ID: "001"}}}}
	requests := map[string]string{
		"000": "ens",
		"001": "ens",
		"002": "ENS ",
		"003": "ens",
		"004": "admins",
	}

	changes, err := Assign(context.Background(), api, requests, []string{"ens"}, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if got := api.assigned["ens"]; !slices.Equal(got, []string{"002", "003"}) {
		t.Errorf("assigned %v, want [002 003]", got)
	}
	if _, ok := api.assigned["admins"]; ok {
		t.Error("an agent joined a group outside the ENS scope")
	}
	if len(changes) != 1 || changes[0].Agents != 2 || !changes[0].Applied {
		t.Errorf("changes = %+v", changes)
	}
}

func TestAssignOnlyRecordsWithoutApply(t *testing.T) {

	api := &fakeAssigner{}

	changes, err := Assign(context.Background(), api, map[string]string{"002": "ens"}, []string{"ens"}, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	if len(api.assigned) != 0 {
		t.Errorf("assigned without -sync-apply: %v", api.assigned)
	}
	if len(changes) != 1 || changes[0].Applied {
		t.Errorf("changes = %+v", changes)
	}
}

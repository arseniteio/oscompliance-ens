package groupconf

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

type fakeWazuh struct {
	members map[string][]string
	confs   map[string]string
	calls   []string
}

func (f *fakeWazuh) GroupNames(context.Context) ([]string, error) {
	var out []string
	for g := range f.members {
		out = append(out, g)
	}
	return out, nil
}

func (f *fakeWazuh) CreateGroup(_ context.Context, name string) error {
	f.calls = append(f.calls, "create "+name)
	f.members[name] = nil
	return nil
}

func (f *fakeWazuh) GroupAgents(_ context.Context, group string) ([]wazuhapi.Agent, error) {
	var out []wazuhapi.Agent
	for _, id := range f.members[group] {
		out = append(out, wazuhapi.Agent{ID: id})
	}
	return out, nil
}

func (f *fakeWazuh) AssignAgents(_ context.Context, group string, ids []string) error {
	f.calls = append(f.calls, "assign "+group+" "+strings.Join(ids, ","))
	f.members[group] = append(f.members[group], ids...)
	return nil
}

func (f *fakeWazuh) RemoveAgents(_ context.Context, group string, ids []string) error {
	f.calls = append(f.calls, "remove "+group+" "+strings.Join(ids, ","))
	f.members[group] = slices.DeleteFunc(f.members[group], func(id string) bool { return slices.Contains(ids, id) })
	return nil
}

func (f *fakeWazuh) GroupConfiguration(_ context.Context, group string) (string, error) {
	return f.confs[group], nil
}

func (f *fakeWazuh) PutGroupConfiguration(_ context.Context, group, conf string) error {
	f.calls = append(f.calls, "conf "+group)
	f.confs[group] = conf
	return nil
}

func TestPublishProfiles(t *testing.T) {

	api := &fakeWazuh{
		members: map[string][]string{"ens": {"001", "002"}, "ens-perfil-ubuntu": {"001", "009"}, "ens-perfil-old": {"002"}},
		confs:   map[string]string{"ens-perfil-ubuntu": ProfileLabels("ubuntu")},
	}
	members := map[string][]string{"ubuntu": {"000", "001", "002"}, "web": {"002"}}
	now := time.Now()

	dry, err := PublishProfiles(context.Background(), api, members, false, now)
	if err != nil || len(api.calls) != 0 || len(dry) == 0 {
		t.Fatalf("without apply nothing is written: %v %v %v", dry, api.calls, err)
	}

	if _, err := PublishProfiles(context.Background(), api, members, true, now); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"remove ens-perfil-old 002",
		"assign ens-perfil-ubuntu 002",
		"remove ens-perfil-ubuntu 009",
		"create ens-perfil-web",
		"assign ens-perfil-web 002",
		"conf ens-perfil-web",
	}
	if !slices.Equal(api.calls, want) {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(api.calls, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(api.confs["ens-perfil-web"], `<label key="ens.perfil.web">true</label>`) {
		t.Errorf("label: %s", api.confs["ens-perfil-web"])
	}

	api.calls = nil
	if changes, _ := PublishProfiles(context.Background(), api, members, true, now); len(changes) != 0 || len(api.calls) != 0 {
		t.Errorf("a second run changes nothing: %v %v", changes, api.calls)
	}
}

package groupconf

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

const ProfileGroupPrefix = catalog.ProfileGroupPrefix

type ProfileAPI interface {
	GroupMaker
	API
	AssignAgents(ctx context.Context, group string, agentIDs []string) error
	RemoveAgents(ctx context.Context, group string, agentIDs []string) error
}

func ProfileGroup(profileID string) string { return ProfileGroupPrefix + profileID }

func ProfileLabels(profileID string) string {
	return "<agent_config>\n  <labels>\n    <label key=\"ens.perfil." + escape(profileID) + "\">true</label>\n  </labels>\n</agent_config>\n"
}

func PublishProfiles(ctx context.Context, api ProfileAPI, members map[string][]string, apply bool, now time.Time) ([]Change, error) {

	existing, err := api.GroupNames(ctx)
	if err != nil {
		return nil, err
	}

	wanted := map[string][]string{}
	for profileID, agents := range members {
		wanted[ProfileGroup(profileID)] = slices.DeleteFunc(slices.Clone(agents), func(id string) bool { return id == "000" })
	}
	for _, g := range existing {
		if _, ok := wanted[g]; !ok && strings.HasPrefix(g, ProfileGroupPrefix) {
			wanted[g] = nil
		}
	}

	var changes []Change
	var errs []error
	for _, group := range slices.Sorted(maps.Keys(wanted)) {
		c, err := publishGroup(ctx, api, group, wanted[group], slices.Contains(existing, group), apply, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("group %s: %w", group, err))
		}
		changes = append(changes, c...)
	}
	return changes, errors.Join(errs...)
}

func publishGroup(ctx context.Context, api ProfileAPI, group string, agents []string, exists, apply bool, now time.Time) ([]Change, error) {

	var changes []Change
	profileID := strings.TrimPrefix(group, ProfileGroupPrefix)

	if !exists {
		if len(agents) == 0 {
			return nil, nil
		}
		if apply {
			if err := api.CreateGroup(ctx, group); err != nil {
				return nil, err
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply})
	}

	var members []wazuhapi.Agent
	if exists {
		var err error
		if members, err = api.GroupAgents(ctx, group); err != nil {
			return changes, err
		}
	}
	current := make([]string, 0, len(members))
	for _, m := range members {
		current = append(current, m.ID)
	}

	joining := missing(agents, current)
	leaving := missing(current, agents)

	if len(joining) > 0 {
		if apply {
			if err := api.AssignAgents(ctx, group, joining); err != nil {
				return changes, err
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply, After: "assigned agents " + strings.Join(joining, ","), Agents: len(joining)})
	}
	if len(leaving) > 0 {
		if apply {
			if err := api.RemoveAgents(ctx, group, leaving); err != nil {
				return changes, err
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply, After: "removed agents " + strings.Join(leaving, ","), Agents: len(leaving)})
	}

	if len(agents) == 0 {
		return changes, nil
	}
	conf := ProfileLabels(profileID)
	before := ""
	if exists {
		var err error
		if before, err = api.GroupConfiguration(ctx, group); err != nil {
			return changes, err
		}
	}
	if !Same(before, conf) {
		if apply {
			if err := api.PutGroupConfiguration(ctx, group, conf); err != nil {
				return changes, err
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply, Before: before, After: conf, Agents: len(agents)})
	}
	return changes, nil
}

func missing(want, have []string) []string {
	in := make(map[string]bool, len(have))
	for _, id := range have {
		in[id] = true
	}
	var out []string
	for _, id := range want {
		if !in[id] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

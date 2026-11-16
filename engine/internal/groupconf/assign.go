package groupconf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/wazuhapi"
)

type Assigner interface {
	GroupAgents(ctx context.Context, group string) ([]wazuhapi.Agent, error)
	AssignAgents(ctx context.Context, group string, agentIDs []string) error
}

func Assign(ctx context.Context, api Assigner, requests map[string]string, groups []string, apply bool, now time.Time) ([]Change, error) {

	var changes []Change
	var errs []error

	for _, group := range slices.Sorted(slices.Values(groups)) {

		requested := requesters(requests, group)
		if len(requested) == 0 {
			continue
		}

		members, err := api.GroupAgents(ctx, group)
		if err != nil {
			errs = append(errs, fmt.Errorf("group %s: %w", group, err))
			continue
		}

		joining := outside(requested, members)
		if len(joining) == 0 {
			continue
		}

		if apply {
			if err := api.AssignAgents(ctx, group, joining); err != nil {
				errs = append(errs, fmt.Errorf("group %s: %w", group, err))
				continue
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply, After: "assigned agents " + strings.Join(joining, ","), Agents: len(joining)})
	}

	return changes, errors.Join(errs...)
}

func OutOfScope(requests map[string]string, groups []string) []string {

	var out []string
	for _, wanted := range requests {
		inScope := slices.ContainsFunc(groups, func(g string) bool { return strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(wanted)) })
		if !inScope && !slices.Contains(out, wanted) {
			out = append(out, wanted)
		}
	}
	slices.Sort(out)

	return out
}

func requesters(requests map[string]string, group string) []string {

	var ids []string
	for id, wanted := range requests {
		if id != "000" && strings.EqualFold(strings.TrimSpace(wanted), strings.TrimSpace(group)) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	return ids
}

func outside(ids []string, members []wazuhapi.Agent) []string {

	in := make(map[string]bool, len(members))
	for _, m := range members {
		in[m.ID] = true
	}

	var out []string
	for _, id := range ids {
		if !in[id] {
			out = append(out, id)
		}
	}

	return out
}

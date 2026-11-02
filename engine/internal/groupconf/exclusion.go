package groupconf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
)

type GroupMaker interface {
	GroupNames(ctx context.Context) ([]string, error)
	CreateGroup(ctx context.Context, name string) error
}

// CreateExclusionGroups creates the group of every control that lacks one. It never deletes: deleting a group
// would take its machines out of it. With apply false it only reports what it would create.
func CreateExclusionGroups(ctx context.Context, api GroupMaker, controls []catalog.Control, apply bool, now time.Time) ([]Change, error) {

	existing, err := api.GroupNames(ctx)
	if err != nil {
		return nil, err
	}

	var changes []Change
	var errs []error

	for _, control := range controls {

		group := catalog.ExclusionGroup(control.Control)
		if slices.Contains(existing, group) {
			continue
		}

		if apply {
			if err := api.CreateGroup(ctx, group); err != nil {
				errs = append(errs, fmt.Errorf("group %s: %w", group, err))
				continue
			}
		}
		changes = append(changes, Change{Group: group, At: now, Applied: apply})
	}

	return changes, errors.Join(errs...)
}

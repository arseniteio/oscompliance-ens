package params

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

const ProfileDocumentType = "PROFILE"

type Source struct {
	Kind string
	ID   string
}

func (s Source) String() string {
	if s.ID == "" {
		return s.Kind
	}
	return s.Kind + " " + s.ID
}

type Resolution struct {
	Value   any
	Mode    string
	Sources []Source
}

func (c *Config) UseProfiles(custom []catalog.Profile) {
	byID := map[string]catalog.Profile{}
	for _, p := range catalog.BuiltinProfiles() {
		byID[p.ID] = p
	}
	for _, p := range custom {
		byID[p.ID] = p
	}
	c.profiles = c.profiles[:0]
	for _, p := range byID {
		c.profiles = append(c.profiles, p)
	}
	slices.SortFunc(c.profiles, func(a, b catalog.Profile) int {
		if d := specificity(b.Layer) - specificity(a.Layer); d != 0 {
			return d
		}
		return strings.Compare(a.ID, b.ID)
	})
	c.assign()
}

func (c *Config) UseHostFacts(facts map[string]catalog.HostFacts) {
	c.hostFacts = facts
	c.assign()
}

func (c *Config) Profiles() []catalog.Profile { return slices.Clone(c.profiles) }

func (c *Config) MatchedProfiles(agentID string) []catalog.Profile {
	return slices.Clone(c.matched[agentID])
}

func (c *Config) KnowsHosts() bool { return c.hostFacts != nil }

func (c *Config) ProfileMembers() map[string][]string {
	out := map[string][]string{}
	for agentID, profiles := range c.matched {
		for _, p := range profiles {
			out[p.ID] = append(out[p.ID], agentID)
		}
	}
	for _, ids := range out {
		slices.Sort(ids)
	}
	return out
}

func (c *Config) assign() {
	c.matched = map[string][]catalog.Profile{}
	for agentID, facts := range c.hostFacts {
		for _, p := range c.profiles {
			if p.Matches(facts) {
				c.matched[agentID] = append(c.matched[agentID], p)
			}
		}
	}
}

func specificity(layer string) int {
	return slices.Index(catalog.Layers, layer)
}

func (c *Config) fromProfiles(agentID, controlID, paramID string) (Resolution, bool) {

	listLike := slices.Contains([]string{"list", "table"}, catalog.ParameterType(controlID, paramID))

	var r Resolution
	var union []any
	seen := map[string]bool{}

	for _, p := range c.matched[agentID] {
		value, ok := p.Values[controlID][paramID]
		if !ok {
			continue
		}
		mode := p.MatchModes[controlID][paramID]
		source := Source{Kind: "profile", ID: p.ID}

		if !listLike || mode == "regex" {
			if len(r.Sources) == 0 {
				return Resolution{Value: value, Mode: mode, Sources: []Source{source}}, true
			}
			continue
		}

		items, err := listValue(value)
		if err != nil {
			continue
		}
		for _, item := range items {
			if key := strings.ToLower(item); !seen[key] {
				seen[key] = true
				union = append(union, item)
			}
		}
		r.Sources = append(r.Sources, source)
		if slices.Contains(p.Replace[controlID], paramID) {
			break
		}
	}

	if len(r.Sources) == 0 {
		return Resolution{}, false
	}
	r.Value = union
	return r, true
}

func (c *Config) Explain(agentID, controlID, paramID string) (Resolution, bool) {
	return c.resolve(agentID, controlID, paramID)
}

func ProfileDocumentID(profileID string) string { return "profile-" + profileID }

func LoadProfiles(ctx context.Context, client *indexer.Client, index string) ([]catalog.Profile, error) {

	query := map[string]any{
		"size":  1000,
		"query": map[string]any{"term": map[string]any{"documentType": ProfileDocumentType}},
	}

	var resp struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Profile catalog.Profile `json:"configuration"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	err := client.Search(ctx, index, query, &resp)
	var missing *indexer.Error
	if errors.As(err, &missing) && missing.Status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var out []catalog.Profile
	var invalid []error
	for _, h := range resp.Hits.Hits {
		p := h.Source.Profile
		if errs := p.Validate(); len(errs) > 0 {
			invalid = append(invalid, fmt.Errorf("profile %s left out: %s", p.ID, strings.Join(errs, "; ")))
			continue
		}
		out = append(out, p)
	}
	return out, errors.Join(invalid...)
}

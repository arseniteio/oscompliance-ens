package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
)

func decodeYAML(raw []byte) ([]catalog.Profile, error) {

	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)

	var out []catalog.Profile
	for n := 1; ; n++ {
		var p catalog.Profile
		err := dec.Decode(&p)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		if p.ID == "" && p.Layer == "" && len(p.Values) == 0 {
			continue
		}
		out = append(out, normalizeProfile(p))
	}
	if len(out) == 0 {
		return nil, errors.New("no profile in the file")
	}
	return out, nil
}

func encodeYAML(profiles []catalog.Profile) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	for _, p := range profiles {
		if err := enc.Encode(p); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// YAML gives int where the indexer gives float64; both sides go through JSON
// so that a number written from a file and read back compares equal.
func normalizeProfile(p catalog.Profile) catalog.Profile {
	for controlID, params := range p.Values {
		for paramID, v := range params {
			p.Values[controlID][paramID] = normalize(v)
		}
	}
	return p
}

func normalize(v any) any {
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(raw, &out) != nil {
		return v
	}
	return out
}

func profileDiff(old, updated catalog.Profile) []string {

	var out []string
	if old.Name != updated.Name {
		out = append(out, "name")
	}
	if old.Description != updated.Description {
		out = append(out, "description")
	}
	if old.Layer != updated.Layer {
		out = append(out, "layer")
	}
	if !slices.Equal(old.Match, updated.Match) {
		out = append(out, "match")
	}

	controls := map[string]bool{}
	for id := range old.Values {
		controls[id] = true
	}
	for id := range updated.Values {
		controls[id] = true
	}
	for _, controlID := range sortedKeys(controls) {
		params := map[string]bool{}
		for id := range old.Values[controlID] {
			params[id] = true
		}
		for id := range updated.Values[controlID] {
			params[id] = true
		}
		for _, paramID := range sortedKeys(params) {
			a, inOld := old.Values[controlID][paramID]
			b, inNew := updated.Values[controlID][paramID]
			name := controlID + " " + paramID
			switch {
			case !inOld:
				out = append(out, name+" added")
			case !inNew:
				out = append(out, name+" removed")
			case !reflect.DeepEqual(normalize(a), normalize(b)) || old.MatchModes[controlID][paramID] != updated.MatchModes[controlID][paramID]:
				out = append(out, name)
			}
		}
	}

	if !reflect.DeepEqual(normalize(old.Replace), normalize(updated.Replace)) {
		out = append(out, "replace")
	}
	return out
}

func shortValue(value any, mode string) string {

	if mode == "regex" {
		return fmt.Sprintf("regex %v", value)
	}

	var items []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			items = append(items, fmt.Sprint(item))
		}
	case []string:
		items = v
	default:
		return fmt.Sprint(value)
	}

	const shown = 3
	if len(items) <= shown {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(items[:shown], ", "), len(items)-shown)
}

func sortedKeys[K cmp.Ordered, V any](m map[K]V) []K {
	return slices.Sorted(maps.Keys(m))
}

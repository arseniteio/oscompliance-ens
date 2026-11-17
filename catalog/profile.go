package catalog

import (
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

const (
	LayerDistro  = "distro"
	LayerRole    = "role"
	LayerService = "service"
	LayerSite    = "site"
)

const ProfileGroupPrefix = "ens-perfil-"

var Layers = []string{LayerDistro, LayerRole, LayerService, LayerSite}

type Profile struct {
	ID          string                       `json:"id" yaml:"id"`
	Name        string                       `json:"name" yaml:"name"`
	Description string                       `json:"description,omitempty" yaml:"description,omitempty"`
	Layer       string                       `json:"layer" yaml:"layer"`
	Match       []Condition                  `json:"match" yaml:"match"`
	Values      map[string]map[string]any    `json:"values" yaml:"values"`
	MatchModes  map[string]map[string]string `json:"match_modes,omitempty" yaml:"match_modes,omitempty"`
	Replace     map[string][]string          `json:"replace,omitempty" yaml:"replace,omitempty"`
	Builtin     bool                         `json:"builtin,omitempty" yaml:"-"`
}

type Condition struct {
	Field string `json:"field" yaml:"field"`
	Op    string `json:"op" yaml:"op"`
	Value string `json:"value" yaml:"value"`
}

type HostFacts struct {
	Distro   string
	Family   string
	Role     string
	Hostname string
	Services []string
	Groups   []string
}

var (
	scalarFields = []string{"distro", "family", "role", "hostname"}
	listFields   = []string{"service", "group"}
	scalarOps    = []string{"is", "is_not", "matches", "in"}
	listOps      = []string{"has", "has_not"}
	profileID    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

func (p Profile) Matches(h HostFacts) bool {
	if len(p.Match) == 0 {
		return false
	}
	for _, c := range p.Match {
		if !c.holds(h) {
			return false
		}
	}
	return true
}

func (c Condition) holds(h HostFacts) bool {
	want := strings.ToLower(strings.TrimSpace(c.Value))
	var got string
	switch c.Field {
	case "distro":
		got = h.Distro
	case "family":
		got = h.Family
	case "role":
		got = h.Role
	case "hostname":
		got = h.Hostname
	case "service":
		return c.Op == "has" == containsFold(h.Services, want)
	case "group":
		return c.Op == "has" == containsFold(h.Groups, want)
	default:
		return false
	}
	got = strings.ToLower(got)
	switch c.Op {
	case "is":
		return got == want
	case "is_not":
		return got != want
	case "matches":
		ok, _ := path.Match(want, got)
		return ok
	case "in":
		return slices.Contains(listOf(want), got)
	}
	return false
}

// A group of machines chosen by hand lists their host names, comma-separated.
func listOf(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func containsFold(list []string, want string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.EqualFold(strings.TrimSpace(s), want) })
}

func (p Profile) Validate() []string {

	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	if !profileID.MatchString(p.ID) {
		add("id %q: use lowercase letters, digits and hyphens", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" {
		add("%s: name is empty", p.ID)
	}
	if !slices.Contains(Layers, p.Layer) {
		add("%s: layer %q is not one of %s", p.ID, p.Layer, strings.Join(Layers, ", "))
	}
	if len(p.Match) == 0 {
		add("%s: match is empty, so the profile would apply to no machine", p.ID)
	}
	for i, c := range p.Match {
		switch {
		case slices.Contains(scalarFields, c.Field):
			if !slices.Contains(scalarOps, c.Op) {
				add("%s: match %d: %s takes %s", p.ID, i+1, c.Field, strings.Join(scalarOps, ", "))
			} else if c.Op == "matches" {
				if _, err := path.Match(c.Value, ""); err != nil {
					add("%s: match %d: bad pattern %q", p.ID, i+1, c.Value)
				}
			} else if c.Op == "in" && len(listOf(c.Value)) == 0 {
				add("%s: match %d: in takes a comma-separated list", p.ID, i+1)
			}
		case slices.Contains(listFields, c.Field):
			if !slices.Contains(listOps, c.Op) {
				add("%s: match %d: %s takes %s", p.ID, i+1, c.Field, strings.Join(listOps, ", "))
			}
			if c.Field == "group" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.Value)), ProfileGroupPrefix) {
				add("%s: match %d: the %s* groups follow the profiles, so a profile cannot depend on them", p.ID, i+1, ProfileGroupPrefix)
			}
		default:
			add("%s: match %d: unknown field %q", p.ID, i+1, c.Field)
		}
		if strings.TrimSpace(c.Value) == "" {
			add("%s: match %d: value is empty", p.ID, i+1)
		}
	}

	for _, controlID := range slices.Sorted(maps.Keys(p.Values)) {
		control, ok := LookupControl(controlID)
		if !ok {
			add("%s: control %s does not exist", p.ID, controlID)
			continue
		}
		for _, paramID := range slices.Sorted(maps.Keys(p.Values[controlID])) {
			param, ok := control.Parameters[paramID]
			switch {
			case !ok:
				add("%s: %s does not exist in %s", p.ID, paramID, controlID)
			case param.Class == ClassOrganisation:
				add("%s: %s %s is set once for the organisation, not per profile", p.ID, controlID, paramID)
			default:
				if msg := checkValue(param, p.Values[controlID][paramID], p.MatchModes[controlID][paramID]); msg != "" {
					add("%s: %s %s: %s", p.ID, controlID, paramID, msg)
				}
			}
		}
	}

	for controlID, params := range p.MatchModes {
		for paramID, mode := range params {
			if mode != "exact" && mode != "regex" {
				add("%s: %s %s: match mode must be exact or regex", p.ID, controlID, paramID)
			}
		}
	}

	for controlID, params := range p.Replace {
		for _, paramID := range params {
			if _, ok := p.Values[controlID][paramID]; !ok {
				add("%s: replace %s %s has no value in this profile", p.ID, controlID, paramID)
			}
		}
	}

	return errs
}

func checkValue(param Parameter, value any, mode string) string {

	if mode == "regex" {
		if s, ok := value.(string); !ok || strings.TrimSpace(s) == "" {
			return "a regular expression must be one non-empty text"
		}
		return ""
	}

	switch param.Type {
	case "list", "table":
		var items []any
		switch v := value.(type) {
		case []any:
			items = v
		case string:
			for _, line := range strings.Split(v, "\n") {
				items = append(items, line)
			}
		default:
			return "must be a list"
		}
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				return fmt.Sprintf("item %v is not text", item)
			}
			if param.Type == "table" && len(param.Columns) > 0 && len(strings.Split(s, "|")) > len(param.Columns) && !param.Columns[len(param.Columns)-1].Variadic {
				return fmt.Sprintf("row %q has more than %d columns", s, len(param.Columns))
			}
		}
	case "number", "duration_days", "duration_hours":
		if _, ok := toFloat(value); !ok {
			return "must be a number"
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return "must be true or false"
		}
	case "select":
		s, ok := value.(string)
		if !ok || (len(param.Options) > 0 && !slices.Contains(param.Options, s)) {
			return fmt.Sprintf("must be one of %s", strings.Join(param.Options, ", "))
		}
	case "string":
		if _, ok := value.(string); !ok {
			return "must be text"
		}
	}
	return ""
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

var builtinProfiles []Profile

func loadProfiles() {
	entries, err := fs.ReadDir(files, "profiles")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		var p Profile
		if err := decodeStrict(path.Join("profiles", e.Name()), &p); err != nil {
			panic(err)
		}
		p.Builtin = true
		builtinProfiles = append(builtinProfiles, p)
	}
}

func BuiltinProfiles() []Profile { return slices.Clone(builtinProfiles) }

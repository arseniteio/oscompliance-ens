package opacc1

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAdminAffixes(t *testing.T) {
	cases := []struct {
		name    string
		rows    []string
		want    []AdminAffix
		problem string
	}{
		{"stored value without position is a suffix", []string{".adm"}, []AdminAffix{{Text: ".adm"}}, ""},
		{"explicit suffix", []string{".adm | sufijo"}, []AdminAffix{{Text: ".adm"}}, ""},
		{"prefix", []string{"adm_ | prefijo"}, []AdminAffix{{Text: "adm_", Prefix: true}}, ""},
		{"both conventions", []string{".adm|sufijo", "adm_|prefijo"}, []AdminAffix{{Text: ".adm"}, {Text: "adm_", Prefix: true}}, ""},
		{"unknown position", []string{".adm | medio"}, nil, "medio"},
		{"empty text", []string{" | prefijo"}, nil, "P-12"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, problem := parseAdminAffixes(c.rows)

			if !reflect.DeepEqual(got, c.want) && c.problem == "" {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
			if c.problem == "" && !problem.IsZero() {
				t.Errorf("unexpected problem %q", problem.Render("en"))
			}
			if c.problem != "" && !strings.Contains(problem.Render("en"), c.problem) {
				t.Errorf("problem %q does not contain %q", problem.Render("en"), c.problem)
			}
		})
	}
}

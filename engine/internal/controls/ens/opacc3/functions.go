package opacc3

import (
	"sort"
	"strings"
)

var accents = strings.NewReplacer("á", "a", "à", "a", "é", "e", "è", "e", "í", "i", "ì", "i", "ï", "i", "ó", "o", "ò", "o", "ú", "u", "ù", "u", "ü", "u")

func normalize(s string) string {
	return accents.Replace(strings.ToLower(strings.TrimSpace(s)))
}

type Function struct {
	Name       string
	Indicators []string
}

func ParseFunctions(rows []string) []Function {

	var out []Function

	for _, r := range rows {
		cells := cells(r)
		if len(cells) < 2 {
			continue
		}
		f := Function{Name: normalize(cells[0])}
		for _, c := range cells[1:] {
			f.Indicators = append(f.Indicators, strings.ToLower(c))
		}
		out = append(out, f)
	}

	return out
}

func Classify(functions []Function, exe, path string) []string {

	hay := strings.ToLower(exe + " " + path)
	seen := map[string]bool{}
	var out []string

	for _, f := range functions {
		for _, i := range f.Indicators {
			if strings.Contains(hay, i) && !seen[f.Name] {
				seen[f.Name] = true
				out = append(out, f.Name)
			}
		}
	}

	sort.Strings(out)
	return out
}

type Pair struct{ Left, Right string }

func ParsePairs(rows []string) []Pair {

	var out []Pair

	for _, r := range rows {
		c := cells(r)
		if len(c) >= 2 {
			out = append(out, Pair{Left: normalize(c[0]), Right: normalize(c[1])})
		}
	}

	return out
}

var requirementPair = map[string]Pair{
	"EV-01": {"desarrollo", "operacion"},
	"EV-02": {"autorizacion", "control"},
	"EV-04": {"configuracion", "mantenimiento"},
	"EV-05": {"auditoria", "*"},
}

func declared(pairs []Pair, want Pair) (Pair, bool) {

	for _, p := range pairs {
		if (p.Left == want.Left && p.Right == want.Right) || (p.Left == want.Right && p.Right == want.Left) {
			if p.Left == "*" {
				p.Left, p.Right = p.Right, p.Left
			}
			return p, true
		}
	}

	return Pair{}, false
}

func Violates(functions map[string]bool, p Pair) bool {

	if !functions[p.Left] {
		return false
	}

	if p.Right != "*" {
		return functions[p.Right]
	}

	for f := range functions {
		if f != p.Left {
			return true
		}
	}
	return false
}

func cells(row string) []string {
	var out []string
	for _, c := range strings.Split(row, "|") {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

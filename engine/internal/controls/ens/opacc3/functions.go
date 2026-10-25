// Package opacc3 judges op.acc.3 (segregation of duties) from what people
// do: the executions and accesses auditd records for the binaries and paths
// of P-03, and the commands run through sudo. Actions are pooled by account
// name across the machines, as v1: the same name is the same person.
package opacc3

import (
	"sort"
	"strings"
)

// accents maps the accented vowels of Spanish, Catalan and Galician
// function names to their plain letter.
var accents = strings.NewReplacer("á", "a", "à", "a", "é", "e", "è", "e", "í", "i", "ì", "i", "ï", "i", "ó", "o", "ò", "o", "ú", "u", "ù", "u", "ü", "u")

// normalize lowercases and strips accents, so "Operación" and "operacion"
// are the same function everywhere (v1 stripped them in one place only).
func normalize(s string) string {
	return accents.Replace(strings.ToLower(strings.TrimSpace(s)))
}

// Function is one P-03 row: a function and the indicators that reveal it.
type Function struct {
	Name       string
	Indicators []string
}

// ParseFunctions reads P-03, "funcion | indicador | indicador...".
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

// Classify gives the functions an action reveals: an indicator found in
// the binary (or command line) or the path, ignoring case.
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

// Pair is a P-02 row: two functions one person may not hold; Right "*" is
// any other function.
type Pair struct{ Left, Right string }

// ParsePairs reads P-02, "a | b".
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

// requirementPair is the pair each requirement is about, as the plugin's
// policy names it.
var requirementPair = map[string]Pair{
	"EV-01": {"desarrollo", "operacion"},
	"EV-02": {"autorizacion", "control"},
	"EV-04": {"configuracion", "mantenimiento"},
	"EV-05": {"auditoria", "*"},
}

// declared finds the requirement's pair among P-02, in either order. A
// reversed wildcard ("* | auditoria") counts as the wildcard (v1 accepted
// it and then never matched).
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

// Violates: the functions hold both sides of the pair.
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

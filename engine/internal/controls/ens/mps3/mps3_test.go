package mps3

import (
	"slices"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestResolvers(t *testing.T) {
	d := &fact.DeviceSecurity{Status: fact.SourceRead, Resolvers: []string{"10.0.0.53", "8.8.8.8"}}
	check(t, "other", JudgeEV05(d, []string{"10.0.0.0/24"}), verdict.NonCompliant, "", "8.8.8.8")
	check(t, "authorised", JudgeEV05(d, []string{"10.0.0.0/24", "8.8.8.8"}), verdict.Compliant, "", "")
	check(t, "anything is no list", JudgeEV05(d, []string{"*"}), verdict.NonCompliant, "", "")
	check(t, "none", JudgeEV05(&fact.DeviceSecurity{Status: fact.SourceRead}, []string{"10.0.0.53"}), verdict.NonCompliant, "", "")
}

func TestRetention(t *testing.T) {
	check(t, "kept", JudgeEV08(400, true, 365), verdict.Compliant, "", "400")
	check(t, "short", JudgeEV08(90, true, 365), verdict.NonCompliant, "", "90")
	check(t, "unknown", JudgeEV08(0, false, 365), verdict.NonCompliant, "", "")
}

func TestCatalogFilters(t *testing.T) {
	c, _ := catalog.LookupControl(control)
	for _, option := range c.Parameters["P-03"].Columns[0].Options {
		key := strings.ReplaceAll(opcont2.Person(option), " ", "_")
		if !slices.ContainsFunc(Filters, func(f struct{ Name, Evidence string }) bool { return f.Name == key }) {
			t.Errorf("option %q (%s) judged by no evidence", option, key)
		}
	}
}

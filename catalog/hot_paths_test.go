package catalog

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestRule119005DropsHotReads(t *testing.T) {

	rules, err := os.ReadFile("wazuh/oscompliance_facts_rules.xml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<rule id="119005".*?<field name="audit.file.name" type="pcre2">([^<]+)</field>`).FindSubmatch(rules)
	if m == nil {
		t.Fatal("rule 119005 has no audit.file.name condition")
	}
	const canonical = `^(?!.*(/\.\.?(/|$)|//))`
	pattern, found := strings.CutPrefix(string(m[1]), canonical)
	if !found {
		t.Fatalf("rule 119005 must refuse names with dot segments or empty segments first: %s", m[1])
	}
	hot := regexp.MustCompile("^" + pattern)
	nonCanonical := regexp.MustCompile(`/\.\.?(/|$)|//`)
	drop := func(name string) bool { return !nonCanonical.MatchString(name) && hot.MatchString(name) }

	for _, p := range HotReadPaths {
		if !drop(p) && !drop(p+"/x") {
			t.Errorf("rule 119005 keeps reads of %s", p)
		}
	}
	for _, p := range []string{"/etc/shadow", "/etc/ssl/private/web.key", "/etc/passwd-", "/srv/datos/x", "/etc/groups.d/x", "/usr/../etc/shadow", "/lib/./../srv/datos/x", "/usr//../etc/shadow", "/etc/ssl/certs/../private/web.key"} {
		if drop(p) {
			t.Errorf("rule 119005 drops reads of %s", p)
		}
	}
}

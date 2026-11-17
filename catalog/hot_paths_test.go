package catalog

import (
	"os"
	"regexp"
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
	drop := regexp.MustCompile(string(m[1]))

	for _, p := range HotReadPaths {
		if !drop.MatchString(p) && !drop.MatchString(p+"/x") {
			t.Errorf("rule 119005 keeps reads of %s", p)
		}
	}
	for _, p := range []string{"/etc/shadow", "/etc/ssl/private/web.key", "/etc/passwd-", "/srv/datos/x", "/etc/groups.d/x"} {
		if drop.MatchString(p) {
			t.Errorf("rule 119005 drops reads of %s", p)
		}
	}
}

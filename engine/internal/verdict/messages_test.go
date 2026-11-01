package verdict

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens/catalog"
)

var says = regexp.MustCompile(`Says\("([a-z0-9_.]+)"`)

// Every message the engine says has its English and Spanish text in the catalog.
func TestEveryCodeHasItsTexts(t *testing.T) {

	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range says.FindAllStringSubmatch(string(src), -1) {
			if strings.HasSuffix(m[1], ".") {
				continue
			}
			for _, lang := range []string{"en", "es"} {
				if _, ok := catalog.Messages(lang)[m[1]]; !ok {
					t.Errorf("%s: %s has no %s text", p, m[1], lang)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

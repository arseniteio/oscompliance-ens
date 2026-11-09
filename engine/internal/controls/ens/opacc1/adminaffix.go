package opacc1

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
)

const adminAffixParam = "P-12"

// AdminAffix is one naming convention that marks an account as the
// administrative identity of a person.
type AdminAffix struct {
	Text   string
	Prefix bool
}

func (a AdminAffix) accountFor(person string) string {
	if a.Prefix {
		return a.Text + person
	}
	return person + a.Text
}

func (a AdminAffix) marks(account string) bool {
	if len(account) <= len(a.Text) {
		return false
	}
	if a.Prefix {
		return strings.HasPrefix(account, a.Text)
	}
	return strings.HasSuffix(account, a.Text)
}

func parseAdminAffixes(rows []string) ([]AdminAffix, catalog.Message) {

	affixes := make([]AdminAffix, 0, len(rows))

	for _, row := range rows {

		affix, problem := parseAdminAffix(row)

		if !problem.IsZero() {
			return nil, catalog.Says("param.invalid", "param", adminAffixParam, "error", problem)
		}

		affixes = append(affixes, affix)
	}

	return affixes, catalog.Message{}
}

func parseAdminAffix(row string) (AdminAffix, catalog.Message) {

	text, position, _ := strings.Cut(row, "|")

	affix := AdminAffix{Text: strings.TrimSpace(text)}

	if affix.Text == "" {
		return AdminAffix{}, catalog.Says("opacc1.admin_affix_empty", "value", row)
	}

	switch strings.ToLower(strings.TrimSpace(position)) {
	case "", "sufijo":
	case "prefijo":
		affix.Prefix = true
	default:
		return AdminAffix{}, catalog.Says("opacc1.admin_affix_position", "value", strings.TrimSpace(position))
	}

	return affix, catalog.Message{}
}

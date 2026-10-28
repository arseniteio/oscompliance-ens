package opacc5

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/passes"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-ens/engine/internal/verdict"
)

var revealing = []struct {
	pattern string
	re      *regexp.Regexp
}{
	{"usuario_inexistente", regexp.MustCompile(`(?i)(usuario|cuenta|user|account)\s+(no\s+existe|inexistente|desconocid[oa]|no\s+encontrad[oa]|not\s+found|does\s+not\s+exist|unknown)|no\s+such\s+user|invalid\s+user(name)?\s*[.!]?\s*$`)},
	{"credencial_incorrecta", regexp.MustCompile(`(?i)^(la\s+)?(contrase[nñ]a|clave|password)\s+(es\s+)?(incorrecta|err[oó]nea|no\s+v[aá]lida|incorrect|wrong|invalid)`)},
	{"estado_de_cuenta", regexp.MustCompile(`(?i)(cuenta|usuario|account|user)\s+(est[aá]\s+)?(bloquead[oa]|caducad[oa]|expirad[oa]|deshabilitad[oa]|inhabilitad[oa]|suspendid[oa]|locked|expired|disabled|suspended)`)},
	{"traza_tecnica", regexp.MustCompile(`(?i)exception|traceback|stack\s*trace|SQLSTATE|ORA-\d+|nginx/\d|apache/\d|version\s+\d+\.\d+`)},
}

func RevealingPattern(message string) string {

	for _, r := range revealing {
		if r.re.MatchString(message) {
			return r.pattern
		}
	}
	return ""
}

type EV06Input struct {
	Services []Service

	Messages   []source.MessageCount
	EverLogged map[string]bool
}

func JudgeEV06(in EV06Input) verdict.Judgement {

	if len(in.Services) == 0 {
		return noService()
	}

	var found []string
	for _, m := range in.Messages {
		if p := RevealingPattern(m.Message); p != "" {
			msg := m.Message
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
			found = append(found, fmt.Sprintf("%s %s %q (%d)", m.Service, p, msg, m.Count))
		}
	}

	if len(found) > 0 {
		sort.Strings(found)
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opacc5.rejections_that_reveal_why_a", "a", found))
	}

	var silent []string
	for _, s := range in.Services {
		if !in.EverLogged[s.Name] {
			silent = append(silent, s.Name)
		}
	}
	if len(silent) > 0 {
		return passes.Gap(verdict.CauseEvidence, catalog.Says("opacc5.no_rejection_message_ever_logged_by_a", "a", silent))
	}

	return verdict.Explain(verdict.Compliant, "", catalog.Says("opacc5.a_rejection_messages_of_the_window_revea", "a", len(in.Messages)))
}

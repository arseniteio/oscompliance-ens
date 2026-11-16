package mps1

import (
	"strings"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func postfixFile(entries ...fact.ConfigEntry) opacc6.Settings {
	return opacc6.Settings{Snapshot: &fact.ConfigSnapshot{RecordsEmitted: 1}, Files: []fact.ConfigFile{{Source: postfix, Status: fact.SourceRead, Entries: entries}}}
}

func TestPlatform(t *testing.T) {
	p := ParsePlatform([]string{"Postfix | mail01 | mail01", "pasarela | | mx-gw"})
	if !p.Runs("MAIL01") || p.Runs("web01") || len(p.Sources) != 2 {
		t.Errorf("platform: %+v", p)
	}
}

func TestTLS(t *testing.T) {
	strong := postfixFile(
		fact.ConfigEntry{Key: "smtpd_tls_security_level", Value: "may"},
		fact.ConfigEntry{Key: "smtp_tls_security_level", Value: "may"},
		fact.ConfigEntry{Key: "smtpd_tls_protocols", Value: ">=TLSv1.2"},
		fact.ConfigEntry{Key: "smtpd_tls_mandatory_protocols", Value: "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"},
		fact.ConfigEntry{Key: "smtp_tls_protocols", Value: ">=TLSv1.2"},
		fact.ConfigEntry{Key: "smtp_tls_mandatory_protocols", Value: ">=TLSv1.2"},
	)
	check(t, "strong", JudgeEV06(strong), verdict.Compliant, "", "")
	weak := postfixFile(fact.ConfigEntry{Key: "smtpd_tls_security_level", Value: "none"})
	check(t, "weak", JudgeEV06(weak), verdict.NonCompliant, "", "smtpd_tls_security_level")
	check(t, "no postfix", JudgeEV06(opacc6.Settings{Snapshot: &fact.ConfigSnapshot{}}), verdict.NonCompliant, "", "")
}

func TestDomains(t *testing.T) {
	good := Domain{Name: "org.es", Selector: "s1", SPF: []string{"v=spf1 mx -all"}, DMARC: []string{"v=DMARC1; p=reject; rua=mailto:d@org.es"}, DKIM: []string{"v=DKIM1; k=rsa; p=MIIB"}}
	check(t, "good", JudgeEV07([]Domain{good}), verdict.Compliant, "", "1")
	bad := Domain{Name: "otro.es", SPF: []string{"v=spf1 +all"}, DMARC: []string{"v=DMARC1; p=none"}}
	check(t, "bad", JudgeEV07([]Domain{good, bad}), verdict.NonCompliant, "", "otro.es (SPF, DKIM, DMARC)")
	check(t, "none", JudgeEV07(nil), verdict.NotEvaluable, verdict.CauseConfiguration, "")
}

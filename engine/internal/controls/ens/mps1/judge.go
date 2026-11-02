package mps1

import (
	"strings"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

func cells(row string, n int) []string { return opcont2.Cells(row, n) }

type Platform struct {
	Machines []string
	Sources  []mpcom1.Element
}

func ParsePlatform(rows []string) Platform {
	var p Platform
	for _, r := range rows {
		c := cells(r, 3)
		if c[1] != "" {
			p.Machines = append(p.Machines, strings.ToLower(c[1]))
		}
		if c[2] != "" {
			p.Sources = append(p.Sources, mpcom1.Element{Name: c[0], Source: c[2]})
		}
	}
	return p
}

func (p Platform) Runs(machine string) bool {
	for _, m := range p.Machines {
		if m == strings.ToLower(machine) {
			return true
		}
	}
	return false
}

const postfix = "/etc/postfix/main.cf"

var weakProtocols = []string{"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

func excluded(list, protocol string) bool {
	if strings.Contains(list, "!"+protocol+",") || strings.Contains(list, "!"+protocol+" ") || strings.HasSuffix(list, "!"+protocol) {
		return true
	}
	return strings.Contains(list, ">=TLSv1.2") || strings.Contains(list, ">=TLSv1.3")
}

func JudgeEV06(settings opacc6.Settings) verdict.Judgement {

	if gap, found := settings.Gap(); found {
		return gap
	}
	values := map[string]string{}
	read := false
	for _, f := range settings.Files {
		if f.Source != postfix {
			continue
		}
		if f.Status == fact.SourceUnreadable || f.Status == fact.SourceError {
			return passes.Gap(verdict.CauseCollection, passes.Source(f.Source, f.Status, f.Error))
		}
		read = f.Status == fact.SourceRead
		for _, e := range f.Entries {
			values[strings.ToLower(e.Key)] = strings.TrimSpace(e.Value)
		}
	}
	if !read {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps1.no_postfix"))
	}

	var weak []string
	if v := values["smtpd_tls_security_level"]; v != "may" && v != "encrypt" {
		weak = append(weak, "smtpd_tls_security_level="+v)
	}
	if v := values["smtp_tls_security_level"]; v == "" || v == "none" {
		weak = append(weak, "smtp_tls_security_level="+v)
	}
	for _, key := range []string{"smtpd_tls_protocols", "smtpd_tls_mandatory_protocols", "smtp_tls_protocols", "smtp_tls_mandatory_protocols"} {
		for _, p := range weakProtocols {
			if !excluded(values[key], p) {
				weak = append(weak, key+" ("+p+")")
				break
			}
		}
	}
	if len(weak) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps1.tls_weak", "list", weak))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps1.tls"))
}

type Domain struct {
	Name, Selector   string
	SPF, DMARC, DKIM []string
}

func JudgeEV07(domains []Domain) verdict.Judgement {

	if len(domains) == 0 {
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("mps1.no_domains"))
	}
	var weak []catalog.Message
	for _, d := range domains {
		var missing []string
		spf := first(d.SPF, "v=spf1")
		if spf == "" || strings.Contains(spf, "+all") || strings.Contains(spf, "?all") || !strings.Contains(spf, "all") {
			missing = append(missing, "SPF")
		}
		if d.Selector == "" || first(d.DKIM, "") == "" {
			missing = append(missing, "DKIM")
		}
		dmarc := strings.ReplaceAll(first(d.DMARC, "v=DMARC1"), " ", "")
		if !strings.Contains(dmarc, "p=quarantine") && !strings.Contains(dmarc, "p=reject") {
			missing = append(missing, "DMARC")
		}
		if len(missing) > 0 {
			weak = append(weak, catalog.Says("item.name_list", "name", d.Name, "list", missing))
		}
	}
	if len(weak) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("mps1.domains_weak", "list", weak))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("mps1.domains", "count", len(domains)))
}

func first(records []string, prefix string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(r), strings.ToLower(prefix)) {
			return r
		}
	}
	return ""
}

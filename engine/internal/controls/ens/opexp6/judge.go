package opexp6

import (
	"slices"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/catalog"
	"github.com/arseniteio/oscompliance-ens-wazuh/catalog/fact"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/passes"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

func gap(p *fact.MalwareProtection) (verdict.Judgement, bool) {
	switch {
	case p == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.MalwareProtectionFact)), true
	case p.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("/proc", p.Status, p.Error)), true
	}
	return verdict.Judgement{}, false
}

func running(p *fact.MalwareProtection) []string {
	var out []string
	for _, a := range p.Products {
		if a.Running {
			out = append(out, a.Product)
		}
	}
	return out
}

var Settings = []string{"proteccion_tiempo_real", "actualizacion_automatica_firmas", "analisis_comprimidos", "registro_syslog"}

func hasClam(p *fact.MalwareProtection) bool {
	return slices.ContainsFunc(p.Products, func(a fact.Antimalware) bool { return a.Product == "clamav" })
}

// The agent reads the signatures, settings and scans of ClamAV and Microsoft Defender only.
func stateRead(p *fact.MalwareProtection) bool {
	return slices.ContainsFunc(p.Products, func(a fact.Antimalware) bool { return a.Product == "clamav" || a.Product == defender })
}

const defender = "windows-defender"

const wazuhProduct = "wazuh"

// WazuhInstalled tells whether the agent read the configuration of the Wazuh
// agent on the machine, the proof that it is installed there.
func WazuhInstalled(c *fact.WazuhAgentConfig) bool {
	return c != nil && c.Status == fact.SourceRead
}

func product(name string) string {
	name = strings.TrimSpace(name)
	if strings.EqualFold(name, wazuhProduct) || strings.EqualFold(name, "wazuh-agent") {
		return wazuhProduct
	}
	return name
}

func JudgeEV01(p *fact.MalwareProtection, expected []string, wazuh bool, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := gap(p); found {
		return j
	}

	wanted := make([]string, 0, len(expected))
	for _, e := range expected {
		wanted = append(wanted, product(e))
	}

	on := running(p)
	if wazuh && slices.Contains(wanted, wazuhProduct) {
		on = append(on, wazuhProduct)
	}
	if len(on) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_antimalware"))
	}
	var missing []string
	for _, e := range wanted {
		if e != "" && !slices.Contains(on, e) {
			missing = append(missing, e)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.not_running", "missing", missing, "running", on))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.running", "running", on))
}

func JudgeEV02(p *fact.MalwareProtection, maxHours int, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := gap(p); found {
		return j
	}
	if j, found := unread(p); found {
		return j
	}

	built, err := time.Parse(time.RFC3339, p.Signatures)
	if err != nil {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_signatures"))
	}
	if age := int(now.Sub(built).Hours()); age > maxHours {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.signatures_old", "built", built.UTC().Format("2006-01-02 15:04"), "hours", age, "max", maxHours))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.signatures_current", "built", built.UTC().Format("2006-01-02 15:04"), "max", maxHours))
}

func unread(p *fact.MalwareProtection) (verdict.Judgement, bool) {
	switch {
	case stateRead(p):
		return verdict.Judgement{}, false
	case len(running(p)) == 0:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_antimalware")), true
	}
	return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.signatures_unread", "products", running(p))), true
}

func yes(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "si", "sí", "yes", "true":
		return true, true
	case "no", "false":
		return false, true
	}
	return false, false
}

func JudgeEV03(p *fact.MalwareProtection, rows []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := gap(p); found {
		return j
	}
	if j, found := unread(p); found {
		return j
	}

	var wrong, right []string
	for _, r := range rows {
		setting, value, _ := strings.Cut(r, "|")
		setting = strings.TrimSpace(setting)
		want, ok := yes(value)
		if !ok {
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("param.not_yes_no", "value", strings.TrimSpace(value)))
		}
		got := slices.Contains(p.Settings, setting)
		switch {
		case !slices.Contains(Settings, setting):
			return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp6.unknown_setting", "setting", setting))
		case got != want:
			wrong = append(wrong, setting)
		default:
			right = append(right, setting)
		}
	}

	if len(wrong) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.settings_wrong", "list", wrong))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.settings_right", "list", right))
}

const (
	ruleDetection = "52502"
	ruleRepeated  = "52511"
)

func JudgeEV04(p *fact.MalwareProtection, alerts []source.AlertCount) verdict.Judgement {

	if j, found := gap(p); found {
		return j
	}
	if hasClam(p) && !slices.Contains(p.Settings, "registro_syslog") {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.clamav_not_in_syslog"))
	}

	detections, repeated := 0, false
	var files []string
	for _, a := range alerts {
		switch a.Rule {
		case ruleDetection:
			detections += a.Count
			files = append(files, a.Examples...)
		case ruleRepeated:
			repeated = true
		}
	}
	slices.Sort(files)
	files = slices.Compact(files)

	switch {
	case repeated:
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.reinfection", "count", detections, "files", files))
	case detections > 0:
		return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.detections", "count", detections, "files", files))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.no_detections"))
}

func JudgeEV05(p *fact.MalwareProtection, maxDays int, problem catalog.Message, now time.Time) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := gap(p); found {
		return j
	}
	if j, found := unread(p); found {
		return j
	}
	last, err := time.Parse(time.RFC3339, p.LastScan)
	if err != nil {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.never_scanned"))
	}
	if age := int(now.Sub(last).Hours() / 24); age > maxDays {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.scan_old", "date", last.UTC().Format("2006-01-02"), "days", age, "max", maxDays))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.scan_recent", "date", last.UTC().Format("2006-01-02 15:04"), "max", maxDays))
}

func wazuhGap(c *fact.WazuhAgentConfig) (verdict.Judgement, bool) {
	switch {
	case c == nil:
		return passes.Gap(verdict.CauseCollection, catalog.Says("gap.no_fact", "fact", fact.WazuhAgentConfigFact)), true
	case c.Status != fact.SourceRead:
		return passes.Gap(verdict.CauseCollection, passes.Source("ossec.conf", c.Status, c.Error)), true
	}
	return verdict.Judgement{}, false
}

func under(path, root string) bool {
	root = strings.TrimRight(root, "/")
	return path == root || strings.HasPrefix(path, root+"/") || root == ""
}

func JudgeEV06(c *fact.WazuhAgentConfig, paths []string, problem catalog.Message) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	if j, found := wazuhGap(c); found {
		return j
	}

	var why []string
	if c.SyscheckDisabled || !c.SyscheckScanOnStart {
		why = append(why, "scan_on_start")
	}
	if c.RootcheckDisabled {
		why = append(why, "rootcheck")
	}
	for _, p := range paths {
		if p = strings.TrimSpace(p); p != "" && !slices.ContainsFunc(c.Directories, func(d fact.FIMDirectory) bool { return under(p, d.Path) }) {
			why = append(why, p)
		}
	}

	if len(why) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.start_unchecked", "list", why))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.start_checked", "count", len(paths)))
}

func JudgeEV07(p *fact.MalwareProtection) verdict.Judgement {

	if j, found := gap(p); found {
		return j
	}
	states := map[string]string{"permissive": "opexp6.allowlist_permissive", "stopped": "opexp6.allowlist_stopped", "absent": "opexp6.allowlist_absent"}
	if p.Allowlist != "enforcing" {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.allowlist", "state", catalog.Says(states[p.Allowlist])))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.allowlist_enforcing"))
}

func Capabilities(rows []string) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		c := strings.Split(r, "|")
		if len(c) < 2 {
			continue
		}
		on, _ := yes(c[1])
		out[strings.ToLower(strings.TrimSpace(c[0]))] = on
	}
	return out
}

func off(capability string) verdict.Judgement {
	return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.capability_off", "capability", capability))
}

func JudgeEV08(on bool, manager *fact.WazuhAgentConfig, c *fact.WazuhAgentConfig, flagged []source.AlertCount) verdict.Judgement {

	if !on {
		return off("virustotal")
	}
	if j, found := wazuhGap(c); found {
		return j
	}
	if manager == nil {
		return passes.Gap(verdict.CauseCollection, catalog.Says("opexp6.manager_config_unknown"))
	}
	if !slices.Contains(manager.Integrations, "virustotal") {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_virustotal"))
	}
	if c.SyscheckDisabled {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp5.fim_disabled"))
	}
	var files []string
	for _, f := range flagged {
		files = append(files, f.Examples...)
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.virustotal", "files", files))
}

func JudgeEV09(on bool, p *fact.MalwareProtection) verdict.Judgement {

	if !on {
		return off("yara")
	}
	if j, found := gap(p); found {
		return j
	}
	if !p.Yara {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_yara"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.yara"))
}

func JudgeEV10(on bool, c *fact.WazuhAgentConfig) verdict.Judgement {

	if !on {
		return off("rootcheck")
	}
	if j, found := wazuhGap(c); found {
		return j
	}
	if c.RootcheckDisabled {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_rootcheck"))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.rootcheck"))
}

func JudgeEV11(on bool, c *fact.WazuhAgentConfig, p *fact.MalwareProtection) verdict.Judgement {

	if !on {
		return off("active_response")
	}
	if j, found := wazuhGap(c); found {
		return j
	}
	if j, found := gap(p); found {
		return j
	}
	if len(c.ActiveResponses) == 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.no_active_response"))
	}
	var missing []string
	for _, r := range c.ActiveResponses {
		if !slices.Contains(p.Responses, r) {
			missing = append(missing, r)
		}
	}
	if len(missing) > 0 {
		return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.responses_missing", "list", missing))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.responses", "list", c.ActiveResponses))
}

func JudgeEV12(policy string, problem catalog.Message, usb []source.AlertCount, p *fact.MalwareProtection) verdict.Judgement {

	if !problem.IsZero() {
		return passes.Gap(verdict.CauseConfiguration, problem)
	}
	attached := 0
	for _, a := range usb {
		attached += a.Count
	}

	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "bloqueados":
		if attached > 0 {
			return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.usb_blocked", "count", attached))
		}
	case "analisis", "análisis":
		if attached > 0 {
			if j, found := gap(p); found {
				return j
			}
			if !slices.Contains(p.Settings, "proteccion_tiempo_real") {
				return verdict.Explain(verdict.NonCompliant, "", catalog.Says("opexp6.usb_unscanned", "count", attached))
			}
		}
	case "lectura":
	default:
		return passes.Gap(verdict.CauseConfiguration, catalog.Says("opexp6.usb_policy", "value", policy))
	}
	return verdict.Explain(verdict.Compliant, "", catalog.Says("opexp6.usb", "count", attached, "policy", policy))
}

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/wazuhapi"
)

// managerState reads what op.mon judges of the manager. Integrations are read without their hook URL or
// API key.
func managerState(ctx context.Context, api *wazuhapi.Client) (*source.Manager, error) {

	m := &source.Manager{}
	var err error

	if m.Daemons, err = api.ManagerStatus(ctx); err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}

	rules, err := api.Rules(ctx)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	for _, r := range rules {
		frequency, _ := strconv.Atoi(text(r.Details["frequency"]))
		correlates := frequency > 0 || text(r.Details["if_matched_sid"]) != "" || text(r.Details["if_matched_group"]) != ""
		m.Rules = append(m.Rules, source.Rule{ID: r.ID, Level: r.Level, File: r.File, Dir: r.Dir, Groups: r.Groups, Mitre: r.Mitre, Frequency: frequency, Correlates: correlates})
	}

	var ruleset struct {
		RuleExclude []string `json:"rule_exclude"`
	}
	if _, err := api.ManagerSection(ctx, "ruleset", &ruleset); err != nil {
		return nil, fmt.Errorf("ruleset: %w", err)
	}
	m.RuleExclude = ruleset.RuleExclude

	var responses []map[string]any
	if _, err := api.ManagerSection(ctx, "active-response", &responses); err != nil {
		return nil, fmt.Errorf("active response: %w", err)
	}
	for _, r := range responses {
		m.Responses = append(m.Responses, source.Response{
			Command: text(r["command"]), Rules: text(r["rules_id"]), Groups: text(r["rules_group"]), Level: text(r["level"]),
			Location: text(r["location"]), Disabled: text(r["disabled"]) == "yes",
		})
	}

	var global map[string]any
	if _, err := api.ManagerSection(ctx, "global", &global); err != nil {
		return nil, fmt.Errorf("global: %w", err)
	}
	m.Email.Enabled = text(global["email_notification"]) == "yes"
	m.Email.To = list(global["email_to"])
	var alerts map[string]any
	if _, err := api.ManagerSection(ctx, "alerts", &alerts); err != nil {
		return nil, fmt.Errorf("alerts: %w", err)
	}
	m.Email.Level, _ = strconv.Atoi(text(alerts["email_alert_level"]))

	var integrations []map[string]any
	if _, err := api.ManagerSection(ctx, "integration", &integrations); err != nil {
		return nil, fmt.Errorf("integration: %w", err)
	}
	for _, i := range integrations {
		level, _ := strconv.Atoi(text(i["level"]))
		m.Integrations = append(m.Integrations, source.Integration{Name: text(i["name"]), Level: level, Groups: text(i["group"])})
	}

	var detector map[string]any
	if _, err := api.ManagerSection(ctx, "vulnerability-detection", &detector); err != nil {
		return nil, fmt.Errorf("vulnerability detection: %w", err)
	}
	m.Vulnerability = text(detector["enabled"]) == "yes"

	pkg, err := api.AgentPackage(ctx, source.ManagerID, "wazuh-manager")
	if err != nil {
		return nil, fmt.Errorf("manager package: %w", err)
	}
	if pkg != nil {
		m.Version = pkg.Version
		m.Installed = installTime(pkg.InstallTime)
	}

	return m, nil
}

func text(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		return strings.Join(list(t), ",")
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func list(v any) []string {
	switch t := v.(type) {
	case []any:
		var out []string
		for _, e := range t {
			if s := text(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if s := strings.TrimSpace(t); s != "" {
			return []string{s}
		}
	}
	return nil
}

// Wazuh writes the install time of a package as its package manager does.
var installLayouts = []string{time.ANSIC, "2006/01/02 15:04:05", time.RFC3339, "2006-01-02 15:04:05"}

func installTime(v string) time.Time {
	for _, layout := range installLayouts {
		if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
			return t
		}
	}
	return time.Time{}
}

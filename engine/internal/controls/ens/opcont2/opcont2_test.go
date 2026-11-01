package opcont2

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog/fact"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

func TestJudges(t *testing.T) {

	plans := []string{"Plan de Continuidad | v2 | 2025-01-10 | Comité | RSEG", "Plan de Continuidad | v3 | 2026-01-15 | Comité | RSEG"}
	check(t, "plan current", JudgeEV01(plans, 12, now), verdict.Compliant, "", "v3")
	check(t, "plan old", JudgeEV01(plans[:1], 12, now), verdict.NonCompliant, "", "v2")
	check(t, "no approval", JudgeEV01([]string{"Plan | v1 | pendiente"}, 12, now), verdict.NonCompliant, "", "")

	means := []string{"CPD alternativo | Proveedor X | CT-2025-014 | 2027-06-30 | 48 h", "línea de respaldo | Operadora | | 2027-01-01 | 4 h", "portátiles | Tienda | CT-1 | 2026-10-01 | 24 h"}
	check(t, "means", JudgeEV04(means, now), verdict.NonCompliant, "", "línea de respaldo")
	check(t, "means covered", JudgeEV04(means[:1], now), verdict.Compliant, "", "CT-2025-014")

	functions := []string{"coordinador de crisis | A. Martínez | J. Ruiz | activar el plan"}
	training := []string{"a. martinez | coordinación | 2026-02-10 | 2027-02-10", "J. Ruiz | coordinación | 2024-02-10 | 2025-02-10"}
	check(t, "untrained", JudgeEV06(functions, training, now), verdict.NonCompliant, "", "J. Ruiz")
	check(t, "trained", JudgeEV06(functions, training[:1], now.AddDate(-1, 0, 0)), verdict.NonCompliant, "", "J. Ruiz")

	config := &fact.WazuhAgentConfig{Status: fact.SourceRead, SyscheckScanOnStart: true, Directories: []fact.FIMDirectory{{Path: "/etc"}, {Path: "/boot"}}}
	check(t, "checked", JudgeEV03(config, []string{"/etc/ssh", "/boot"}), verdict.Compliant, "", "2")
	check(t, "unwatched", JudgeEV03(config, []string{"/opt/app"}), verdict.NonCompliant, "", "/opt/app")
	config.SyscheckScanOnStart = false
	check(t, "no scan on start", JudgeEV03(config, nil), verdict.NonCompliant, "", "")
}

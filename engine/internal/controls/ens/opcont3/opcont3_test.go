package opcont3

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var tests = ParseTests([]string{
	"2026-03-14T22:00:00Z | 2026-03-15T02:00:00Z | Simulacro | pérdida total de CPD | web01, db01 | satisfactorio | 2 | INF-1",
	"2025-06-01 | 2025-06-01 | revisión documental | ciberincidente | | satisfactorio | 0 | INF-0",
})

func TestPlanning(t *testing.T) {

	if len(tests) != 2 || tests[1].Kind != "simulacro" || !tests[1].Involves("WEB01") {
		t.Fatalf("parsed: %+v", tests)
	}
	period := Since(tests, now.AddDate(0, -12, 0))
	check(t, "exercised", JudgeEV01(period, []string{"simulacro | conmutación | 12"}), verdict.Compliant, "", "simulacro")
	check(t, "none planned", JudgeEV01(period, []string{"escritorio | | 12"}), verdict.NonCompliant, "", "")

	check(t, "periodic", JudgeEV02(tests, []string{"simulacro | | 12"}, []string{"pérdida total de CPD | todos"}, 12, now), verdict.Compliant, "", "")
	check(t, "overdue", JudgeEV02(tests, []string{"revisión documental | | 6"}, []string{"ciberincidente"}, 12, now), verdict.NonCompliant, "", "ciberincidente")
}

func TestDowntime(t *testing.T) {

	at := func(m int) time.Time { return time.Date(2026, 3, 14, 22, m, 0, 0, time.UTC) }
	records := []source.MonitoringRecord{
		{Time: at(0), Status: "active"}, {Time: at(5), Status: "disconnected"}, {Time: at(10), Status: "disconnected"},
		{Time: at(40), Status: "active"}, {Time: at(45), Status: "active"},
	}
	down, restored, ok := Downtime(records, at(0), at(59))
	if !ok || !restored || down != 35*time.Minute {
		t.Errorf("got %s %v %v", down, restored, ok)
	}

	m := []Measured{{Test: tests[1], Down: down, Restored: true, Seen: true}}
	check(t, "rto met", JudgeEV04(m, []string{"web01 | 0,5 | 10"}, "web01"), verdict.Compliant, "", "")
	check(t, "rto missed", JudgeEV04(m, []string{"web01 | 0,5 | 0"}, "web01"), verdict.NonCompliant, "", "35m")
	check(t, "no rto", JudgeEV04(m, nil, "web01"), verdict.NotEvaluable, verdict.CauseConfiguration, "")
	check(t, "unseen", JudgeEV03([]Measured{{Test: tests[1]}}), verdict.NotEvaluable, verdict.CauseEvidence, "2026-03-14")
}

func TestDeficiencies(t *testing.T) {
	rows := []string{"D-1 | 2026-03-14 | RSIS | 2026-04-30 | cerrada | 2026-04-20 | v3.1", "D-2 | 2026-03-14 | RSIS | 2026-12-31 | abierta | | "}
	check(t, "followed", JudgeEV05(tests, rows, now), verdict.Compliant, "", "2")
	check(t, "late", JudgeEV05(tests, rows, time.Date(2027, 1, 10, 0, 0, 0, 0, time.UTC)), verdict.NonCompliant, "", "D-2")
	check(t, "unfollowed", JudgeEV05(tests, rows[:1], now), verdict.NonCompliant, "", "2026-03-14")
}

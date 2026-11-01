package opexp9

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/catalog"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var incidents = opexp7.Of(opexp7.ParseRegister([]string{
	"INC-1 | inicial | 2026-10-27 10:00 | alta | web01 | | RSI | | no | | no | | https://intra/INC-1 | ",
	"INC-1 | final | 2026-10-28 09:00 | alta | web01 | | | | no | | no | medidas | | 2026-11-20",
	"INC-2 | inicial | 2026-10-29 08:00 | critica | web01 | | | | | | si | | | ",
}), "web01", now)

func TestJudges(t *testing.T) {

	none := func(from, to time.Time) (int, error) { return 0, nil }
	some := func(from, to time.Time) (int, error) { return 3, nil }
	check(t, "events lost", JudgeEV01(incidents, none), verdict.NonCompliant, "", "INC-1, INC-2")
	check(t, "events kept", JudgeEV01(incidents, some), verdict.Compliant, "", "2 incidents")

	check(t, "reports", JudgeEV02(incidents, Due([]string{"inicial | | 0", "intermedio | | 12", "final | | 0"}), catalog.Message{}), verdict.NonCompliant, "", "INC-1 (intermedio)")

	changes := []opexp5.Change{{Time: time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC), What: "/etc/ssh/sshd_config (modified)"}}
	check(t, "changes", JudgeEV04(incidents, changes, nil, "web01", catalog.Message{}, now), verdict.NonCompliant, "", "sshd_config")

	check(t, "legal without reference", JudgeEV05(incidents, nil, now), verdict.NonCompliant, "", "INC-2")
	check(t, "period kept", JudgeEV07(incidents, some, now), verdict.Compliant, "", "1 open or legal")

	check(t, "review late", JudgeEV08(incidents, []string{"alta | 7 | revisión"}, catalog.Message{}, now), verdict.NonCompliant, "", "INC-1")
	check(t, "record", JudgeEV09(incidents), verdict.NonCompliant, "", "INC-2 (referencia)")
}

package opnub1

import (
	"strings"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
)

var now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func check(t *testing.T, name string, got verdict.Judgement, status verdict.Status, cause verdict.Cause, reason string) {
	t.Helper()
	if got.Status != status || got.Cause != cause || !strings.Contains(got.Reason, reason) {
		t.Errorf("%s: got %s %s %q, want %s %s containing %q", name, got.Status, got.Cause, got.Reason, status, cause, reason)
	}
}

var integrations = Integrations([]string{"AWS producción | aws-s3 | cuenta 123", "M365 | office365 | inquilino", "Correo | ninguno | "})

func TestLogs(t *testing.T) {
	if len(integrations) != 2 {
		t.Fatalf("integrations: %v", integrations)
	}
	logs := map[string]source.Detection{"aws-s3": {Last: now.Add(-time.Hour)}, "office365": {Last: now.Add(-48 * time.Hour)}}
	check(t, "silent", JudgeEV01(integrations, logs, 24, now), verdict.NonCompliant, "", "M365")
	logs["office365"] = source.Detection{Last: now.Add(-time.Minute)}
	check(t, "flowing", JudgeEV01(integrations, logs, 24, now), verdict.Compliant, "", "AWS")
	check(t, "none", JudgeEV01(nil, logs, 24, now), verdict.NonCompliant, "", "")
	check(t, "unknown module", JudgeEV01([]Integration{{"X", "oci"}}, logs, 24, now), verdict.NotEvaluable, verdict.CauseConfiguration, "")
}

func TestAdmins(t *testing.T) {
	ops := []source.CloudOperation{
		{Module: "aws-s3", Actor: "arn:aws:iam::123:role/Admin", Operation: "PutBucketPolicy", Count: 3},
		{Module: "office365", Actor: "intruso@example.org", Operation: "Add member to role.", Count: 1},
	}
	admins := []string{"AWS producción | arn:aws:iam::123:role/Admin", "M365 | admin@example.org"}
	check(t, "unknown admin", JudgeEV04(integrations, ops, admins), verdict.NonCompliant, "", "intruso@example.org")
	check(t, "known", JudgeEV04(integrations, ops[:1], admins), verdict.Compliant, "", "3")
	check(t, "unread module", JudgeEV04([]Integration{{"GitHub", "github"}}, ops, admins), verdict.NotEvaluable, verdict.CauseEvidence, "GitHub")
}

func TestRecord(t *testing.T) {
	used := Used([]string{"AWS producción | IaaS | Amazon | expedientes | alta | utilizado", "Sede | SaaS | propia | | | prestado"})
	if len(used) != 1 {
		t.Fatalf("used: %v", used)
	}
	check(t, "certified", JudgeEV08(used, []string{"aws producción | ENECSTI | CCN-1 | 2027-03-31"}, now), verdict.Compliant, "", "1")
	check(t, "expired", JudgeEV08(used, []string{"AWS producción | ENECSTI | CCN-1 | 2026-03-31"}, now), verdict.NonCompliant, "", "AWS")

	r := Record{
		Conformity:    []string{"AWS producción | ENS ALTA | todo | 2027-01-01 | DC-1"},
		Jurisdiction:  []string{"AWS producción | UE (Irlanda) | UE | RGPD"},
		Encryption:    []string{"AWS producción | AES-256 | KMS con CMK"},
		Pentests:      []string{"AWS producción | resumen 2025 | 2025-02-15 | plataforma"},
		PentestMonths: 12,
	}
	check(t, "pentest old", JudgeEV09(used, r, now), verdict.NonCompliant, "", "pentest")
	r.Pentests = append(r.Pentests, "AWS producción | resumen 2026 | 2026-02-15 | plataforma")
	check(t, "complete", JudgeEV09(used, r, now), verdict.Compliant, "", "")
}

func TestDecisions(t *testing.T) {
	ids := []string{"op.nub.1.1", "op.nub.1.2", "op.nub.1.r1.1", "op.nub.1.r2.1"}
	if d := Decisions("usuario", ids); len(d) != 1 || d["op.nub.1.1"].Status != verdict.NotApplicable {
		t.Errorf("user: %v", d)
	}
	if d := Decisions("ninguna", ids); len(d) != 4 {
		t.Errorf("neither: %v", d)
	}
	if d := Decisions("ambos", ids); len(d) != 0 {
		t.Errorf("both: %v", d)
	}
}

func TestPosture(t *testing.T) {
	week := source.Detection{Last: now.Add(-time.Hour), Count: 40}
	check(t, "clean", JudgeEV02([]Posture{{Service: "AWS", Group: "aws_securityhub", All: week}}, 12, now), verdict.Compliant, "", "1")
	check(t, "serious", JudgeEV02([]Posture{{Service: "AWS", Group: "aws_securityhub", All: week, Serious: source.Detection{Count: 3}}}, 12, now), verdict.NonCompliant, "", "AWS")
	check(t, "silent", JudgeEV02([]Posture{{Service: "Azure", Group: "ms-graph"}}, 12, now), verdict.NonCompliant, "", "ms-graph")
	check(t, "none", JudgeEV02(nil, 12, now), verdict.NonCompliant, "", "")
}

package mpinfo6

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

var copies = ParseCopies([]string{
	"diaria | /srv/copias/diaria | | ",
	"etc | git:/etc/ | 48 | 7",
	"sin ruta | copias | 1 | 1",
})

var snapshot = fact.BackupSnapshot{Status: fact.SourceRead, Sources: []fact.BackupSource{
	{Source: "/srv/copias/diaria", Status: fact.SourceRead, Newest: "2026-11-01T02:00:00Z", Oldest: "2026-10-10T02:00:00Z", Files: 22, NewestBytes: 1024, Mode: "0750", Owner: "root:backup", GroupReadable: 22, Filesystem: "nfs4", Device: "nas01:/copias"},
	{Source: "git:/etc", Status: fact.SourceRead, Newest: "2026-10-28T03:00:00Z", Oldest: "2026-10-30T03:00:00Z", Files: 4, Mode: "0755", Owner: "root:root", Filesystem: "ext4", Device: "/dev/sda1"},
}, KeyFiles: []fact.BackupKey{{Path: "/root/key.json", Status: fact.SourceRead, Mode: "0644", Owner: "root:root"}}}

func TestParseCopies(t *testing.T) {
	if len(copies) != 2 || copies[1].Source != "git:/etc" || copies[1].Hours != 48 || copies[0].Name != "diaria" {
		t.Errorf("got %+v", copies)
	}
}

func TestJudges(t *testing.T) {

	read, _, ok := Read(&snapshot, copies)
	if !ok {
		t.Fatal("not read")
	}
	_, gap, _ := Read(&fact.BackupSnapshot{Status: fact.SourceRead}, copies)
	check(t, "not read", gap, verdict.NotEvaluable, verdict.CauseCollection, "")

	check(t, "done", JudgeEV01(copies, read), verdict.Compliant, "", "2 copies")
	empty := map[string]fact.BackupSource{"/srv/copias/diaria": {Status: fact.SourceRead, Newest: "2026-11-01T02:00:00Z", Files: 3}, "git:/etc": read["git:/etc"]}
	check(t, "empty", JudgeEV01(copies, empty), verdict.NonCompliant, "", "diaria")

	check(t, "late", JudgeEV02(copies, read, 24, 2, now), verdict.NonCompliant, "", "etc")
	check(t, "no interval", JudgeEV02(copies, read, 0, 0, now), verdict.NotEvaluable, verdict.CauseConfiguration, "")

	check(t, "retention", JudgeEV03(copies, read, 30, now), verdict.NonCompliant, "", "diaria")
	check(t, "retention kept", JudgeEV03(copies[1:], read, 30, now.AddDate(0, 0, 10)), verdict.Compliant, "", "etc")

	check(t, "group outside", JudgeEV04(copies, read, snapshot.KeyFiles, nil, []string{"root"}), verdict.NonCompliant, "", "backup")
	check(t, "key open", JudgeEV04(copies, read, snapshot.KeyFiles, []string{"/root/key.json"}, []string{"root", "backup"}), verdict.NonCompliant, "", "0644")
	check(t, "closed", JudgeEV04(copies, read, nil, nil, []string{"root", "backup"}), verdict.Compliant, "", "")
	check(t, "key not read", JudgeEV04(copies, read, nil, []string{"/root/key.json"}, []string{"root", "backup"}), verdict.NotEvaluable, verdict.CauseCollection, "")

	check(t, "offsite", JudgeEV06(copies, read), verdict.Compliant, "", "nas01")
	check(t, "local only", JudgeEV06(copies[1:], read), verdict.NonCompliant, "", "")
}

func TestRestores(t *testing.T) {
	rows := Restores([]string{"2026-10-20 | web01 | diaria | correcta | sha256", "2026-10-30 | web01 | diaria | fallida | ", "2026-10-31 | db01 | diaria | correcta | "}, "WEB01")
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "2026-10-20") {
		t.Errorf("got %v", rows)
	}
}

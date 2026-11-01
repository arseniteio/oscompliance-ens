package backups

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func TestCollect(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "etc", ".git", "logs", "HEAD"),
		"0000 1111 root <root@h> 1761000000 +0000\tcommit (initial): first\n1111 2222 root <root@h> 1761700000 +0000\tcommit: daily autocommit\n")
	old := filepath.Join(dir, "backups", "etc-1.tar.gz")
	collecttest.Write(t, old, "x")
	collecttest.Write(t, filepath.Join(dir, "backups", "etc-2.tar.gz"), "y")
	if err := os.Chtimes(old, time.Unix(1700000000, 0), time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}

	sources := []string{"git:" + filepath.Join(dir, "etc"), filepath.Join(dir, "backups", "etc-*.tar.gz"), filepath.Join(dir, "none", "*.tar")}
	f := collecttest.Facts(t, func(e *emit.Emitter) error { return collect(e, sources, true) })[0]

	got := f["sources"].([]any)
	if git := got[0].(map[string]any); git["newest"] != "2025-10-29T01:06:40Z" {
		t.Errorf("git: %v", git)
	}
	if files := got[1].(map[string]any); files["status"] != "read" || files["newest"] == "2023-11-14T22:13:20Z" {
		t.Errorf("newest file: %v", files)
	}
	if none := got[2].(map[string]any); none["status"] != "absent" {
		t.Errorf("no copy: %v", none)
	}

	if f := collecttest.Facts(t, func(e *emit.Emitter) error { return collect(e, nil, false) })[0]; f["status"] != "absent" {
		t.Errorf("not configured: %v", f)
	}
}

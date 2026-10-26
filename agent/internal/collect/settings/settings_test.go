package settings

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/collect/collecttest"
	"github.com/OpenSourceCompliance/oscompliance-ens/agent/internal/emit"
	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

func TestParseEntries(t *testing.T) {

	in := `# comment
PASS_MAX_DAYS	90
ENV_PATH PATH=/usr/bin:/bin
minlen = 12
dictcheck=1
enforce_for_root
[Journal]
Storage=none
Match User backup
	PasswordAuthentication yes
`
	got, err := parseEntries(strings.NewReader(in), false)
	if err != nil {
		t.Fatal(err)
	}

	want := []fact.ConfigEntry{
		{Key: "PASS_MAX_DAYS", Value: "90", Line: 2},
		{Key: "ENV_PATH", Value: "PATH=/usr/bin:/bin", Line: 3},
		{Key: "minlen", Value: "12", Line: 4},
		{Key: "dictcheck", Value: "1", Line: 5},
		{Key: "enforce_for_root", Value: "", Line: 6},
		{Key: "Storage", Value: "none", Line: 8, Section: "Journal"},
		{Key: "Match", Value: "User backup", Line: 9},
		{Key: "PasswordAuthentication", Value: "yes", Line: 10, Section: "Match User backup"},
	}

	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCollectConfig(t *testing.T) {

	dir := t.TempDir()
	collecttest.Write(t, filepath.Join(dir, "login.defs"), "PASS_MAX_DAYS 99999\n")
	collecttest.Write(t, filepath.Join(dir, "pwquality.conf.d", "b.conf"), "minlen = 14\n")
	collecttest.Write(t, filepath.Join(dir, "pwquality.conf.d", "a.conf"), "minlen = 10\n")

	facts := collecttest.Facts(t, func(e *emit.Emitter) error {
		return Collect(e, Config{Files: []string{
			filepath.Join(dir, "login.defs"),
			filepath.Join(dir, "faillock.conf"),
			filepath.Join(dir, "pwquality.conf.d", "*.conf"),
		}})
	})

	if len(facts) != 5 {
		t.Fatalf("got %d facts, want 4 sources and the snapshot", len(facts))
	}

	if facts[1]["status"] != "absent" {
		t.Errorf("missing faillock.conf: got %v", facts[1]["status"])
	}

	if !strings.HasSuffix(facts[2]["source"].(string), "a.conf") || !strings.HasSuffix(facts[3]["source"].(string), "b.conf") {
		t.Errorf("drop-in order: %v, %v", facts[2]["source"], facts[3]["source"])
	}

	if facts[4]["fact"] != "config_snapshot" || facts[4]["records_emitted"] != 4.0 {
		t.Errorf("snapshot: %v", facts[4])
	}
}

func TestParseSambaEntries(t *testing.T) {

	got, err := parseEntries(strings.NewReader("[global]\n  map to guest = Bad User\n[public]\n  guest   ok = yes\n; comment\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != "map to guest" || got[1].Key != "guest ok" || got[1].Value != "yes" || got[1].Section != "public" {
		t.Errorf("samba: %+v", got)
	}
}

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDefaultsWithoutConfigFile(t *testing.T) {
	opts, err := loadOptions(filepath.Join(t.TempDir(), "missing.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, defaultOptions()) {
		t.Fatalf("got %+v", opts)
	}
}

func TestNamedConfigFileMustExist(t *testing.T) {
	if _, err := loadOptions(filepath.Join(t.TempDir(), "missing.json"), true); err == nil {
		t.Fatal("no error for a missing configuration file that was asked for")
	}
}

func TestConfigOverridesOnlyWhatItSets(t *testing.T) {
	opts, err := loadOptions(writeConfig(t, `{"sweep_timeout": "5m", "paths": {"sudoers": "/usr/local/etc/sudoers"}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	want := defaultOptions()
	want.SweepTimeout.Duration = 5 * time.Minute
	want.Paths.Sudoers = "/usr/local/etc/sudoers"
	if !reflect.DeepEqual(opts, want) {
		t.Fatalf("got %+v, want %+v", opts, want)
	}
}

func TestConfigRejectsUnknownKeys(t *testing.T) {
	if _, err := loadOptions(writeConfig(t, `{"sudoers": "/etc/sudoers"}`), true); err == nil {
		t.Fatal("a misplaced key was accepted")
	}
}

func TestExampleConfigIsTheDefaults(t *testing.T) {
	opts, err := loadOptions("../../agent.example.json", true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opts, defaultOptions()) {
		t.Fatalf("agent.example.json differs from the defaults: %+v", opts)
	}
}

func TestUnknownCollector(t *testing.T) {
	if _, err := selectCollectors([]string{"identity", "nope"}); err == nil {
		t.Fatal("an unknown collector was accepted")
	}
}

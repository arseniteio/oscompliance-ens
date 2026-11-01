package collecttest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
)

func Facts(t *testing.T, collect func(*emit.Emitter) error) []map[string]any {
	t.Helper()

	var buf bytes.Buffer
	if err := collect(emit.New(&buf, "h", "test", "5f0c7a1e-2b9d-4c3e-9a51-6d2f8e4b7c10")); err != nil {
		t.Fatal(err)
	}

	var facts []map[string]any
	for _, line := range bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n")) {
		var f map[string]any
		if err := json.Unmarshal(line, &f); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		facts = append(facts, f)
	}
	return facts
}

func WriteFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func Write(t *testing.T, path, content string) {
	t.Helper()
	WriteFile(t, path, content, 0o644)
}

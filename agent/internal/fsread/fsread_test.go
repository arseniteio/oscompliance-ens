package fsread

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestOpenRefusesFIFO(t *testing.T) {

	fifo := filepath.Join(t.TempDir(), "authorized_keys")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no mkfifo:", err)
	}

	done := make(chan error, 1)
	go func() { _, err := Open(fifo); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO must be refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Open blocked on a FIFO")
	}

	regular := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(regular); err != nil || string(data) != "x" {
		t.Errorf("regular file: %q %v", data, err)
	}
}

package winps

import (
	"errors"
	"testing"
)

func TestDecodeSkipsTheByteOrderMark(t *testing.T) {
	got, err := Decode[map[string]int](Static("\xef\xbb\xbf{\"a\":1}"), "")
	if err != nil || got["a"] != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestDecodeReportsBadOutput(t *testing.T) {
	if _, err := Decode[map[string]int](Static("WARNING: x"), ""); err == nil {
		t.Fatal("no error for output that is not JSON")
	}
}

func TestDecodePassesTheRunError(t *testing.T) {
	want := errors.New("boom")
	if _, err := Decode[map[string]int](Failing(want), ""); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
}

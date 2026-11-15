package indexer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRejectsAnEmptyURLList(t *testing.T) {
	if _, err := New(" , ", "", "", ""); err == nil {
		t.Fatal("New accepted a list with no URL")
	}
}

func TestSendFailsOverToTheNextIndexer(t *testing.T) {

	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer up.Close()

	client, err := New(downURL+", "+up.URL+"/", "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	var out struct{ OK bool }
	if err := client.Do(context.Background(), http.MethodGet, "/", nil, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if !out.OK {
		t.Fatal("answer not decoded")
	}
	if client.baseURL() != up.URL {
		t.Fatalf("client stays on %s, want %s", client.baseURL(), up.URL)
	}
}

func TestSendFailsWhenEveryIndexerIsDown(t *testing.T) {

	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close()

	client, err := New(downURL+","+downURL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Do(context.Background(), http.MethodGet, "/", nil, nil); err == nil {
		t.Fatal("Do succeeded with every indexer down")
	}
}

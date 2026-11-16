package wazuhapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoLogsInAgainWhenTheTokenIsRevoked(t *testing.T) {

	tokenRetryDelay = 0
	defer func() { tokenRetryDelay = 2 * time.Second }()

	var logins, calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/security/user/authenticate") {
			n := logins.Add(1)
			_, _ = w.Write([]byte("token-" + string(rune('0'+n))))
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer token-1" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"title": "Unauthorized", "detail": "Invalid token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data": {"affected_items": [{"name": "ens"}], "total_affected_items": 1}}`))
	}))
	defer server.Close()

	client, err := New(server.URL, "oscompliance", "secret", "", "")
	if err != nil {
		t.Fatal(err)
	}

	names, err := client.GroupNames(context.Background())
	if err != nil {
		t.Fatalf("GroupNames: %v", err)
	}
	if len(names) != 1 || names[0] != "ens" {
		t.Errorf("names = %v", names)
	}
	if logins.Load() != 2 || calls.Load() != 2 {
		t.Errorf("logins = %d, calls = %d, want 2 and 2", logins.Load(), calls.Load())
	}
}

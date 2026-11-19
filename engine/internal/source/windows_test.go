package source

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

func hitsIndexer(t *testing.T, alerts ...map[string]any) *Source {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var hits []any
		for i, a := range alerts {
			hits = append(hits, map[string]any{"_id": string(rune('a' + i)), "_source": a})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hits": map[string]any{"hits": hits}})
	}))
	t.Cleanup(server.Close)

	client, err := indexer.New(server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return New(client, "alerts", "monitoring", "states")
}

func winEvent(id string, data map[string]any) map[string]any {
	return map[string]any{
		"id": "w" + id, "timestamp": "2026-11-17T10:00:00.000+0000", "agent": map[string]any{"id": "045"},
		"rule": map[string]any{"id": "60106"},
		"data": map[string]any{"win": map[string]any{"system": map[string]any{"eventID": id}, "eventdata": data}},
	}
}

func TestWindowsLoginsAreInteractiveOnly(t *testing.T) {

	s := hitsIndexer(t,
		winEvent("4624", map[string]any{"targetUserName": "ana", "logonType": "10", "ipAddress": "10.0.0.7", "authenticationPackageName": "Negotiate"}),
		winEvent("4624", map[string]any{"targetUserName": "ana", "logonType": "2", "ipAddress": "-"}),
		winEvent("4624", map[string]any{"targetUserName": "svc-control", "logonType": "3", "ipAddress": "10.0.0.9"}),
		winEvent("4624", map[string]any{"targetUserName": "DC01$", "logonType": "2"}),
		winEvent("4624", map[string]any{"targetUserName": "SYSTEM", "logonType": "2"}),
	)

	logins, err := s.logins(context.Background(), []string{"045"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	got := logins["045"]
	if len(got) != 2 {
		t.Fatalf("got %+v, want the RDP and the console login only", got)
	}
	if got[0].Method != MethodRDP || got[0].SourceIP != "10.0.0.7" || got[0].Account != "ana" || !Remote(got[0].Method) {
		t.Errorf("rdp %+v", got[0])
	}
	if got[1].Method != MethodConsole || got[1].SourceIP != "" {
		t.Errorf("console %+v", got[1])
	}
}

func TestWindowsFailuresAndLockouts(t *testing.T) {

	s := hitsIndexer(t,
		winEvent("4625", map[string]any{"targetUserName": "ana", "ipAddress": "10.0.0.7"}),
		winEvent("4625", map[string]any{"targetUserName": "DC01$", "ipAddress": "10.0.0.8"}),
		winEvent("4625", map[string]any{"targetUserName": "SYSTEM"}),
		winEvent("4740", map[string]any{"targetUserName": "ana"}),
		winEvent("4740", map[string]any{"targetUserName": "WS01$"}),
	)

	failures, err := s.failures(context.Background(), []string{"045"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if f := failures["045"]; len(f) != 1 || f[0].Account != "ana" || f[0].SourceIP != "10.0.0.7" {
		t.Errorf("failures %+v", f)
	}

	lockouts, err := s.lockouts(context.Background(), []string{"045"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if l := lockouts["045"]; len(l) != 1 || l[0].Account != "ana" {
		t.Errorf("lockouts %+v", l)
	}
}

func TestWindowsFileAccessesAreAuditAccesses(t *testing.T) {

	s := hitsIndexer(t, map[string]any{
		"timestamp": "2026-11-17T10:00:05.000+0000", "agent": map[string]any{"id": "045"}, "rule": map[string]any{"id": FactRule},
		"data": map[string]any{"fact": "file_access", "time": "2026-11-17T09:59:30.1234567Z", "watch": `C:\ProgramData\ssh`, "path": `C:\ProgramData\ssh\ssh_host_ed25519_key`, "access": "read", "account": "ana", "process_name": `C:\Windows\notepad.exe`},
	})

	got, err := s.auditAccesses(context.Background(), []string{"045"}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	a := got["045"]
	if len(a) != 1 || a[0].Key != "oscompliance_read" || a[0].Account != "ana" || a[0].AUID != "" || a[0].Exe != `C:\Windows\notepad.exe` || a[0].Time.Second() != 30 {
		t.Errorf("got %+v", a)
	}
}

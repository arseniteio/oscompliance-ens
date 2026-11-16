package params

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/engine/internal/indexer"
)

func indexerAnswering(t *testing.T, status int, body string) *indexer.Client {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	client, err := indexer.New(server.URL, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestLoadReportsNotSavedWhenTheIndexIsMissing(t *testing.T) {

	client := indexerAnswering(t, http.StatusNotFound, `{"error": {"type": "index_not_found_exception"}}`)

	if _, err := Load(context.Background(), client, "wazuh-ens-configuration"); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("Load error = %v, want ErrNotSaved", err)
	}
}

func TestLoadReportsNotSavedWhenNoConfigurationIsActive(t *testing.T) {

	client := indexerAnswering(t, http.StatusOK, `{"hits": {"hits": []}}`)

	if _, err := Load(context.Background(), client, "wazuh-ens-configuration"); !errors.Is(err, ErrNotSaved) {
		t.Fatalf("Load error = %v, want ErrNotSaved", err)
	}
}

func TestLoadKeepsOtherIndexerErrors(t *testing.T) {

	client := indexerAnswering(t, http.StatusForbidden, `{"error": "no permissions"}`)

	_, err := Load(context.Background(), client, "wazuh-ens-configuration")
	if err == nil || errors.Is(err, ErrNotSaved) {
		t.Fatalf("Load error = %v, want a permission error", err)
	}
}

func TestDefaultScopesTheEnsGroup(t *testing.T) {

	c := Default()

	if c.Level() != "MEDIO" {
		t.Errorf("Level() = %q, want MEDIO", c.Level())
	}
	if groups := c.Groups(); len(groups) != 1 || groups[0] != "ens" {
		t.Errorf("Groups() = %v, want [ens]", groups)
	}
	if !c.Evaluates("001", []string{"default", "ens"}) || c.Evaluates("002", []string{"default"}) {
		t.Error("Evaluates does not follow the ens group")
	}
	if !c.ControlEnabled("op.acc.1") {
		t.Error("controls must be enabled by default")
	}
}

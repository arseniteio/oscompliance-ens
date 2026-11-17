package winupdate

import (
	"testing"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/collect/collecttest"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/winps"
)

const sample = `{"last_search":"2026-11-17T05:12:00.0000000Z","pending":3,"security":1,"search_error":"","history":[
{"date":"2026-11-12T02:00:00.0000000Z","title":"2026-11 Cumulative Update (KB5050001)","operation":1},
{"date":"2026-11-12T02:00:00.0000000Z","title":"Security Intelligence Update (KB2267602)","operation":1},
{"date":"2026-10-01T02:00:00.0000000Z","title":"Old tool (KB1)","operation":2}]}`

func TestStatus(t *testing.T) {
	m := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectStatus(e, winps.Static(sample)) })[0]
	if m["manager"] != Manager || m["lists_updated"] != "2026-11-17T05:12:00Z" || m["pending"] != 3.0 || m["security"] != 1.0 {
		t.Errorf("got %v", m)
	}
}

func TestSearchErrorIsAGap(t *testing.T) {
	m := collecttest.Facts(t, func(e *emit.Emitter) error {
		return CollectStatus(e, winps.Static(`{"search_error":"0x8024402C","history":[]}`))
	})[0]
	if m["status"] != "error" || m["error"] != "0x8024402C" {
		t.Errorf("got %v", m)
	}
}

func TestTransactionsGroupedByTime(t *testing.T) {
	facts := collecttest.Facts(t, func(e *emit.Emitter) error { return CollectTransactions(e, winps.Static(sample)) })
	if len(facts) != 3 {
		t.Fatalf("got %v", facts)
	}
	if facts[0]["start"] != "2026-10-01T02:00:00Z" || len(facts[0]["removed"].([]any)) != 1 {
		t.Errorf("first %v", facts[0])
	}
	if len(facts[1]["installed"].([]any)) != 2 || facts[1]["actor"] != "Windows Update" {
		t.Errorf("second %v", facts[1])
	}
	if facts[2]["records_emitted"] != 2.0 {
		t.Errorf("snapshot %v", facts[2])
	}
}

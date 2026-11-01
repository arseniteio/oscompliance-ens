package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/engine/internal/indexer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oscompliance-fleetsim:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("indexer", "https://localhost:9200", "indexer URL")
	user := flag.String("user", "admin", "indexer user; password in OSC_INDEXER_PASSWORD")
	ca := flag.String("ca", "", "CA certificate of the indexer")
	source := flag.String("source-index", "wazuh-alerts-*", "where the template agent's alerts are")
	template := flag.String("agent", "001", "agent copied")
	alerts := flag.String("alerts-index", "wazuh-alerts-4.x-fleetsim", "index the simulated alerts go to")
	monitoring := flag.String("monitoring-index", "wazuh-monitoring-fleetsim", "index the simulated agents are registered in")
	agents := flag.Int("agents", 1000, "simulated agents")
	first := flag.Int("first-id", 10000, "first simulated agent ID")
	hours := flag.Int("hours", 26, "hourly passes per agent")
	group := flag.String("group", "ens", "Wazuh group the simulated agents belong to")
	quiet := flag.Bool("quiet", false, "unchanged collectors send nothing; each pass ends with agent_pass")
	keepalive := flag.Bool("keepalive", false, "only refresh the agents' monitoring record, as Wazuh does every few minutes")
	fullAge := flag.Int("full-hours-ago", 0, "with -quiet, age of the full pass in hours (0: the oldest hourly pass)")
	flag.Parse()

	ctx := context.Background()
	client, err := indexer.New(*addr, *user, os.Getenv("OSC_INDEXER_PASSWORD"), *ca)
	if err != nil {
		return err
	}

	docs, err := templateDocs(ctx, client, *source, *template)
	if err != nil {
		return err
	}
	pass, natives := split(docs)
	if len(pass) == 0 {
		return fmt.Errorf("agent %s has no full pass in the last day", *template)
	}
	fmt.Printf("template: %d facts in a full pass, %d native alerts\n", len(pass), len(natives))

	loud := map[string]bool{"auth_log_probe": true, "file_sweep_snapshot": true}
	for _, d := range pass {
		if d["data"].(map[string]any)["fact"] == "service_log" {
			loud["service_log_snapshot"] = true
		}
	}

	var quietFacts []string
	for _, d := range pass {
		fact, _ := d["data"].(map[string]any)["fact"].(string)
		if !isRecord(fact) && !loud[fact] {
			quietFacts = append(quietFacts, fact)
		}
	}

	now := time.Now().UTC()
	var body bytes.Buffer
	sent := 0

	flush := func() error {
		if body.Len() == 0 {
			return nil
		}
		err := client.Bulk(ctx, body.Bytes())
		body.Reset()
		return err
	}
	add := func(index string, doc map[string]any) error {
		action, _ := json.Marshal(map[string]any{"index": map[string]any{"_index": index}})
		line, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		body.Write(action)
		body.WriteByte('\n')
		body.Write(line)
		body.WriteByte('\n')
		sent++
		if body.Len() > 8<<20 {
			return flush()
		}
		return nil
	}

	for i := 0; i < *agents; i++ {

		id, name := fmt.Sprintf("%05d", *first+i), fmt.Sprintf("sim-%05d", *first+i)

		if err := add(*monitoring, map[string]any{"id": id, "name": name, "group": []string{*group}, "status": "active", "timestamp": now.Format(time.RFC3339)}); err != nil {
			return err
		}
		if *keepalive {
			continue
		}

		full := uuid()
		for h := *hours - 1; h >= 0; h-- {
			at := now.Add(-time.Duration(h)*time.Hour - time.Duration(i%3600)*time.Second)
			run := full
			if h != *hours-1 {
				run = uuid()
			} else if *quiet && *fullAge > 0 {
				at = now.Add(-time.Duration(*fullAge)*time.Hour - time.Duration(i%3600)*time.Second)
			}
			for _, d := range pass {
				fact, _ := d["data"].(map[string]any)["fact"].(string)
				record := isRecord(fact)
				if record && run != full {
					continue
				}
				if *quiet && run != full && !loud[fact] {
					continue
				}
				doc := retarget(d, id, name, at)
				data := doc["data"].(map[string]any)
				data["run_id"], data["ts"], data["host"] = run, at.Format(time.RFC3339), name
				if run != full && hasRecords(fact) {
					data["records_run_id"] = full
				}
				if err := add(*alerts, doc); err != nil {
					return err
				}

				if fact == "auth_log_probe" {
					if err := add(*alerts, probe(id, name, run, at)); err != nil {
						return err
					}
				}
			}
			if *quiet {
				var inForce []any
				for _, f := range quietFacts {
					inForce = append(inForce, f+":"+full)
				}
				doc := retarget(pass[0], id, name, at)
				delete(doc, "full_log")
				doc["data"] = map[string]any{
					"oscompliance": "1", "fact": "agent_pass", "ts": at.Format(time.RFC3339), "host": name,
					"agent_version": pass[0]["data"].(map[string]any)["agent_version"], "run_id": run, "in_force": inForce,
				}
				if err := add(*alerts, doc); err != nil {
					return err
				}
			}
		}

		for j, d := range natives {
			at := now.Add(-time.Duration(j%(*hours))*time.Hour - time.Duration(i%3600)*time.Second)
			if err := add(*alerts, retarget(d, id, name, at)); err != nil {
				return err
			}
		}

		if (i+1)%100 == 0 {
			fmt.Printf("%d agents, %d documents\n", i+1, sent)
		}
	}

	if err := flush(); err != nil {
		return err
	}
	fmt.Printf("done: %d agents, %d documents\n", *agents, sent)
	return nil
}

func templateDocs(ctx context.Context, client *indexer.Client, index, agent string) ([]map[string]any, error) {

	query := map[string]any{
		"size": 10000,
		"sort": []any{map[string]any{"timestamp": "desc"}},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"agent.id": agent}},
			map[string]any{"range": map[string]any{"timestamp": map[string]any{"gte": "now-24h"}}},
		}}},
	}

	var resp struct {
		Hits struct {
			Hits []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := client.Search(ctx, index, query, &resp); err != nil {
		return nil, err
	}

	var out []map[string]any
	for _, h := range resp.Hits.Hits {
		out = append(out, h.Source)
	}
	return out, nil
}

func split(docs []map[string]any) (pass, natives []map[string]any) {

	full := ""
	for _, d := range docs {
		data, _ := d["data"].(map[string]any)
		if data["fact"] == "identity_snapshot" && data["records_run_id"] == nil {
			full, _ = data["run_id"].(string)
			break
		}
	}

	for _, d := range docs {
		rule, _ := d["rule"].(map[string]any)
		data, _ := d["data"].(map[string]any)
		switch rule["id"] {
		case "119001":
			if data["run_id"] == full {
				pass = append(pass, d)
			}
		case "119002":
		default:
			natives = append(natives, d)
		}
	}
	return pass, natives
}

func isRecord(fact string) bool {
	return !strings.HasSuffix(fact, "_snapshot") && fact != "auth_log_probe" && fact != "wazuh_agent_config"
}

func hasRecords(fact string) bool {
	switch fact {
	case "identity_snapshot", "group_snapshot", "sudoers_snapshot", "config_snapshot", "pam_snapshot",
		"listening_snapshot", "service_log_snapshot", "acl_snapshot", "file_sweep_snapshot":
		return true
	}
	return false
}

func retarget(d map[string]any, id, name string, at time.Time) map[string]any {

	raw, _ := json.Marshal(d)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)

	agent, _ := doc["agent"].(map[string]any)
	if agent == nil {
		agent = map[string]any{}
	}
	agent["id"], agent["name"] = id, name
	doc["agent"] = agent
	doc["timestamp"] = at.Format("2006-01-02T15:04:05.000-0700")
	doc["@timestamp"] = at.Format(time.RFC3339)
	doc["id"] = fmt.Sprintf("%d.%s", at.UnixNano(), id)
	return doc
}

func probe(id, name, run string, at time.Time) map[string]any {
	return map[string]any{
		"timestamp":  at.Format("2006-01-02T15:04:05.000-0700"),
		"@timestamp": at.Format(time.RFC3339),
		"agent":      map[string]any{"id": id, "name": name},
		"rule":       map[string]any{"id": "119002", "level": 3, "groups": []any{"oscompliance", "oscompliance_probe"}},
		"full_log":   at.Format(time.RFC3339) + " " + name + " oscompliance-agent[1]: auth log probe " + run,
		"id":         fmt.Sprintf("%d.%s.probe", at.UnixNano(), id),
	}
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

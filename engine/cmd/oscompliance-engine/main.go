package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpcom4"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpeq2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpeq3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/mpinfo6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc4"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opacc6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opcont3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp10"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp4"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp5"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp6"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp7"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp8"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opexp9"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon2"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opmon3"
	"github.com/arseniteio/oscompliance-ens/engine/internal/controls/ens/opnub1"
	"github.com/arseniteio/oscompliance-ens/engine/internal/evaluator"
	"github.com/arseniteio/oscompliance-ens/engine/internal/groupconf"
	"github.com/arseniteio/oscompliance-ens/engine/internal/indexer"
	"github.com/arseniteio/oscompliance-ens/engine/internal/params"
	"github.com/arseniteio/oscompliance-ens/engine/internal/run"
	"github.com/arseniteio/oscompliance-ens/engine/internal/source"
	"github.com/arseniteio/oscompliance-ens/engine/internal/store"
	"github.com/arseniteio/oscompliance-ens/engine/internal/verdict"
	"github.com/arseniteio/oscompliance-ens/engine/internal/wazuhapi"
)

var version = "dev"

const (
	passwordEnv    = "OSC_INDEXER_PASSWORD"
	apiPasswordEnv = "OSC_WAZUH_API_PASSWORD"
)

func main() {
	if err := runMain(); err != nil {
		slog.Error("oscompliance-engine", "error", err)
		os.Exit(1)
	}
}

func runMain() error {
	indexerURL := flag.String("indexer", "https://wazuh.indexer:9200", "indexer URL")
	user := flag.String("user", "admin", "indexer user; password in $"+passwordEnv+"; least privilege: catalog/wazuh/engine-role.yml")
	caFile := flag.String("ca", "", "CA certificate for the indexer (PEM)")
	alerts := flag.String("alerts-index", "wazuh-alerts-*", "index pattern holding the facts")
	monitoring := flag.String("monitoring-index", "wazuh-monitoring-*", "index pattern listing the registered agents")
	states := flag.String("states-prefix", "wazuh-states-", "prefix of Wazuh's state indices (inventory)")
	verdicts := flag.String("verdicts-index", "oscompliance-verdicts", "index the verdicts are written to")
	configIndex := flag.String("config-index", "wazuh-ens-configuration", "plugin index holding the policy parameters")
	historyIndex := flag.String("history-index", "oscompliance-identity-history", "index of the per-account history (EV-08)")
	window := flag.Duration("window", 26*time.Hour, "only facts newer than this count")
	lookback := flag.Duration("lookback", 7*24*time.Hour, "agents with facts this recent are judged")
	interval := flag.Duration("interval", 0, "time between passes; 0 runs one pass and exits")
	apiURL := flag.String("wazuh-api", "", "Wazuh API URL; empty leaves the group configuration alone")
	apiUser := flag.String("wazuh-api-user", "oscompliance", "Wazuh API user; password in $"+apiPasswordEnv+"; least privilege: catalog/wazuh/engine-api-role.json")
	apiCA := flag.String("wazuh-api-ca", "", "certificate the Wazuh API is trusted with (PEM)")
	apiServerName := flag.String("wazuh-api-server-name", "", "name checked in the Wazuh API certificate, when it differs from the URL host")
	syncInterval := flag.Duration("sync-interval", 15*time.Minute, "minimum time between two group configuration syncs")
	syncApply := flag.Bool("sync-apply", false, "write the group configuration; without it the changes are only logged and recorded")
	configHistoryIndex := flag.String("config-history-index", "oscompliance-config-history", "index recording every group configuration change")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	password := os.Getenv(passwordEnv)
	if password == "" {
		return fmt.Errorf("$%s is not set", passwordEnv)
	}
	if *lookback < *window {
		return fmt.Errorf("-lookback (%s) must not be shorter than -window (%s)", *lookback, *window)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := indexer.New(*indexerURL, *user, password, *caFile)
	if err != nil {
		return err
	}

	sink, err := store.NewVerdicts(ctx, client, *verdicts)
	if err != nil {
		return fmt.Errorf("verdicts index: %w", err)
	}

	hist, err := store.NewHistory(ctx, client, *historyIndex)
	if err != nil {
		return fmt.Errorf("history index: %w", err)
	}

	facts := source.New(client, *alerts, *monitoring, *states)

	var groups *groupSync
	if *apiURL != "" {
		apiPassword := os.Getenv(apiPasswordEnv)
		if apiPassword == "" {
			return fmt.Errorf("$%s is not set", apiPasswordEnv)
		}
		api, err := wazuhapi.New(*apiURL, *apiUser, apiPassword, *apiCA, *apiServerName)
		if err != nil {
			return err
		}
		history, err := store.NewConfigHistory(ctx, client, *configHistoryIndex)
		if err != nil {
			return fmt.Errorf("config history index: %w", err)
		}
		groups = &groupSync{api: api, history: history, every: *syncInterval, apply: *syncApply}
		facts.UseManagerInventory(func(ctx context.Context) (*source.Inventory, error) { return managerInventory(ctx, api) })
		facts.UseManager(func(ctx context.Context) (*source.Manager, error) { return managerState(ctx, api) })
		facts.UseManagerNetwork(func(ctx context.Context, tools []string) (*source.Network, error) {
			return managerNetwork(ctx, api, tools)
		})
	}

	controls := []evaluator.Evaluator{
		opacc1.NewEvaluator(facts, hist),
		opacc2.NewEvaluator(facts),
		opacc3.NewEvaluator(facts),
		opacc4.NewEvaluator(facts),
		opacc5.NewEvaluator(facts),
		opacc6.NewEvaluator(facts, hist),
		opexp1.NewEvaluator(facts),
		opexp2.NewEvaluator(facts),
		opexp3.NewEvaluator(facts),
		opexp4.NewEvaluator(facts),
		opexp5.NewEvaluator(facts),
		opexp6.NewEvaluator(facts),
		opexp7.NewEvaluator(facts),
		opexp8.NewEvaluator(facts),
		opexp9.NewEvaluator(facts),
		opexp10.NewEvaluator(facts),
		mpinfo6.NewEvaluator(facts),
		opmon1.NewEvaluator(facts),
		opmon2.NewEvaluator(facts),
		opmon3.NewEvaluator(facts),
		opcont2.NewEvaluator(facts),
		opcont3.NewEvaluator(facts),
		opnub1.NewEvaluator(facts),
		mpcom1.NewEvaluator(facts),
		mpcom3.NewEvaluator(facts),
		mpcom4.NewEvaluator(facts),
		mpeq2.NewEvaluator(facts),
		mpeq3.NewEvaluator(facts),
	}
	cfg := run.Config{
		Window: *window, Lookback: *lookback, EngineVersion: version,
		Plan: func(agents []verdict.Agent) {
			facts.Plan(agents)
			hist.Plan(agents)
		},
		Flush: hist.Flush,
	}

	for {

		var policy params.Lister
		if loaded, err := params.Load(ctx, client, *configIndex); err != nil {
			slog.Warn("parameters", "error", err)
			policy = params.Unavailable(err)
		} else {
			if platforms, err := facts.Platforms(ctx, time.Now().Add(-*lookback)); err != nil {
				slog.Warn("inventory platforms", "error", err)
			} else {
				loaded.UseInventoryTypes(platforms)
			}
			policy = loaded
			groups.run(ctx, loaded, time.Now())
		}

		start, before := time.Now(), client.Requests()
		n, err := run.Once(ctx, facts, controls, policy, sink, cfg, time.Now())
		took, requests := time.Since(start).Round(time.Millisecond), client.Requests()-before
		if err != nil {
			slog.Error("pass", "verdicts", n, "seconds", took.Seconds(), "requests", requests, "error", err)
		} else {
			slog.Info("pass", "verdicts", n, "seconds", took.Seconds(), "requests", requests)
		}

		if *interval == 0 {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*interval):
		}
	}
}

type groupSync struct {
	api     *wazuhapi.Client
	history *store.ConfigHistory
	every   time.Duration
	apply   bool
	last    time.Time
}

// run keeps the group configuration in step with the parameters. A failed sync never stops the
// pass: the verdicts still come out, and the next sync tries again.
func (g *groupSync) run(ctx context.Context, policy *params.Config, now time.Time) {

	if g == nil || now.Sub(g.last) < g.every {
		return
	}
	g.last = now

	groups := policy.Groups()
	if len(groups) == 0 {
		slog.Warn("group configuration", "error", "the ENS scope names no Wazuh group: the engine only configures a scope by group")
		return
	}

	changes, err := groupconf.Sync(ctx, g.api, policy, groups, g.apply, now)
	for _, c := range changes {
		slog.Info("group configuration", "group", c.Group, "agents", c.Agents, "applied", c.Applied)
		if err := g.history.Write(ctx, c); err != nil {
			slog.Warn("group configuration history", "group", c.Group, "error", err)
		}
	}
	if err != nil {
		slog.Error("group configuration", "error", err)
	}
}

func managerInventory(ctx context.Context, api *wazuhapi.Client) (*source.Inventory, error) {

	s, err := api.AgentSyscollector(ctx, source.ManagerID)
	if err != nil {
		return nil, err
	}

	inv := &source.Inventory{Packages: s.Packages, Vendors: s.Vendors, Addresses: s.Addresses, Listening: s.Listening, Processes: s.Processes}
	if s.HasOS {
		inv.System = &source.System{OS: s.OS, Version: s.Version, Kernel: s.Kernel, Architecture: s.Architecture}
	}
	if s.HasHardware {
		inv.Hardware = &source.Hardware{Cores: s.Cores, MemoryMB: int(s.MemoryKB / 1024)}
	}
	return inv, nil
}

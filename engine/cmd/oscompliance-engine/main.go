// Command oscompliance-engine reads facts from the Wazuh indexer, judges them
// and writes verdicts to their own index. With -interval it keeps running.
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

	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/indexer"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/params"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/run"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/source"
	"github.com/OpenSourceCompliance/oscompliance-core/engine/internal/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// passwordEnv holds the indexer password; never a flag, so it stays out of ps.
const passwordEnv = "OSC_INDEXER_PASSWORD"

func main() {
	if err := runMain(); err != nil {
		slog.Error("oscompliance-engine", "error", err)
		os.Exit(1)
	}
}

func runMain() error {
	indexerURL := flag.String("indexer", "https://wazuh.indexer:9200", "indexer URL")
	user := flag.String("user", "admin", "indexer user; password in $"+passwordEnv)
	caFile := flag.String("ca", "", "CA certificate for the indexer (PEM)")
	alerts := flag.String("alerts-index", "wazuh-alerts-*", "index pattern holding the facts")
	verdicts := flag.String("verdicts-index", "oscompliance-verdicts", "index the verdicts are written to")
	configIndex := flag.String("config-index", "wazuh-ens-configuration", "plugin index holding the policy parameters")
	historyIndex := flag.String("history-index", "oscompliance-identity-history", "index of the per-account history (EV-08)")
	window := flag.Duration("window", 26*time.Hour, "only facts newer than this count")
	lookback := flag.Duration("lookback", 7*24*time.Hour, "agents with facts this recent are judged")
	interval := flag.Duration("interval", 0, "time between passes; 0 runs one pass and exits")
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

	facts := source.New(client, *alerts)
	cfg := run.Config{Window: *window, Lookback: *lookback, EngineVersion: version}

	for {
		// Reloaded every pass: a change in the Configuration screen applies
		// on the next pass without restarting the engine.
		var policy params.Lister
		if loaded, err := params.Load(ctx, client, *configIndex); err != nil {
			slog.Warn("parameters", "error", err)
			policy = params.Unavailable(err)
		} else {
			policy = loaded
		}

		n, err := run.Once(ctx, facts, policy, hist, sink, cfg, time.Now())
		if err != nil {
			slog.Error("pass", "verdicts", n, "error", err)
		} else {
			slog.Info("pass", "verdicts", n)
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

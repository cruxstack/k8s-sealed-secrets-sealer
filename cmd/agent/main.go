// Command agent runs beside a sealed-secrets controller in each cluster.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agent"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadAgent()
	if err != nil {
		return err
	}
	logger := cfg.Logging.Logger(os.Stdout).With(
		"component", "agent",
		"controller", cfg.ControllerNamespace+"/"+cfg.ControllerName,
	)
	slog.SetDefault(logger)

	restCfg, err := agent.RESTConfig(cfg.KubeContext)
	if err != nil {
		return err
	}
	certs, err := agent.NewControllerCertSource(restCfg, cfg.ControllerNamespace, cfg.ControllerName)
	if err != nil {
		return err
	}
	a := agent.New(agent.Options{
		Certs:    certs,
		Interval: cfg.InventoryInterval,
		Logger:   logger,
		Version:  version.Version,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(ctx, "starting agent", "version", version.Version)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	g.Go(func() error { return httpserver.Serve(ctx, cfg.HTTPAddr, a.Handler(), logger) })
	return g.Wait()
}

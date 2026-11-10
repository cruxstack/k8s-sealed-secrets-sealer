// Command server runs the control plane as an HTTP server, for containers
// and local development.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/app"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfgs, err := config.LoadControlPlanes(ctx)
	if err != nil {
		return err
	}
	cfg := cfgs[0]
	logger := cfg.Logging.Logger(os.Stdout).With("component", "control-plane")
	if len(cfgs) == 1 {
		logger = logger.With("env", cfg.EnvName)
	}
	slog.SetDefault(logger)

	handler, err := app.NewControlPlane(ctx, cfgs, logger)
	if err != nil {
		return err
	}
	return httpserver.Serve(ctx, cfg.HTTPAddr, handler, logger)
}

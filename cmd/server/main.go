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

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/controlplane"
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
	cfg, err := config.LoadControlPlane()
	if err != nil {
		return err
	}
	logger := cfg.Logging.Logger(os.Stdout).With("component", "control-plane")
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(ctx, "starting control plane", "version", version.Version)
	srv := controlplane.New(controlplane.Options{Logger: logger, Version: version.Version})
	return httpserver.Serve(ctx, cfg.HTTPAddr, srv.Handler(), logger)
}

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
	"k8s.io/client-go/kubernetes"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agent"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
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
	kube, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	inventory := agent.NewInventory(agent.InventoryOptions{
		Certs:      certs,
		Kube:       kube,
		Namespace:  cfg.ControllerNamespace,
		Name:       cfg.ControllerName,
		Deployment: cfg.ControllerDeployment,
		ListKeys:   cfg.HasCapability(protocol.CapabilityKeys),
		Logger:     logger,
	})
	client := agent.NewClient(agent.ClientOptions{
		BaseURL:   cfg.ControlPlaneURL,
		TokenFile: cfg.TokenFile,
		Version:   version.Version,
	})
	a := agent.New(agent.Options{
		Inventory:    inventory,
		ControlPlane: client,
		Interval:     cfg.CheckInInterval,
		Capabilities: cfg.Capabilities,
		Logger:       logger,
		Version:      version.Version,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(ctx, "starting agent",
		"version", version.Version, "control_plane", cfg.ControlPlaneURL, "capabilities", cfg.Capabilities)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	g.Go(func() error { return httpserver.Serve(ctx, cfg.HTTPAddr, a.Handler(), logger) })
	return g.Wait()
}

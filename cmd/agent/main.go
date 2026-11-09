// Command agent runs beside a sealed-secrets controller in each cluster.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
	identity, err := newIdentity(cfg)
	if err != nil {
		return err
	}
	client := agent.NewClient(agent.ClientOptions{
		BaseURL:  cfg.ControlPlaneURL,
		Identity: identity,
		Version:  version.Version,
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
		"version", version.Version, "control_plane", cfg.ControlPlaneURL, "identity", cfg.IdentityMode,
		"capabilities", cfg.Capabilities)
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	g.Go(func() error { return httpserver.Serve(ctx, cfg.HTTPAddr, a.Handler(), logger) })
	return g.Wait()
}

// newIdentity returns how the agent logs in. In AWS mode the credentials
// come from the SDK's default chain: EKS Pod Identity or IRSA in a cluster.
func newIdentity(cfg *config.Agent) (agent.Identity, error) {
	if cfg.IdentityMode != protocol.MethodAWSSTS {
		return agent.K8sTokenIdentity{TokenFile: cfg.TokenFile}, nil
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	region := cfg.AWSSTSRegion
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return nil, errors.New("aws-sts identity needs a region: set APP_AWS_STS_REGION or AWS_REGION")
	}
	return agent.NewAWSIdentity(agent.AWSIdentityOptions{
		Credentials: awsCfg.Credentials,
		Region:      region,
		Audience:    cfg.IdentityAudience,
	})
}

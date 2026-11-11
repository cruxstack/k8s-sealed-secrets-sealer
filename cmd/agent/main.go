// Command agent runs beside a sealed-secrets controller in each cluster.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"golang.org/x/sync/errgroup"
	"k8s.io/client-go/dynamic"
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
	if cfg.MemoryLimit > 0 {
		// collect harder near the container's limit than be killed at it
		debug.SetMemoryLimit(cfg.MemoryLimit / 10 * 9)
	}

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
		BaseURL:         cfg.ControlPlaneURL,
		Identity:        identity,
		Env:             cfg.EnvName,
		Version:         version.Version,
		CheckInInterval: cfg.CheckInInterval,
		Logger:          logger,
	})

	// a handler is registered only for capabilities this agent has; commands
	// expire in the control plane's time
	commands := agent.NewCommands(client, logger, client.Now)
	if cfg.HasCapability(protocol.CapabilitySeal) {
		kmsClient, err := newKMS(cfg, cfg.KMSTransitKeyID)
		if err != nil {
			return err
		}
		sealer := agent.NewSealer(agent.SealerOptions{
			// while the controller restarts, seal with the keys it reported
			// last, for as long as the control plane counts this agent
			// healthy without a check-in
			Keys:         inventory.Fallback(protocol.HealthWindow(cfg.CheckInInterval)),
			KMS:          kmsClient,
			TransitKeyID: cfg.KMSTransitKeyID,
			Env:          cfg.EnvName,
			AgentID:      client.AgentID,
			Logger:       logger,
		})
		commands.Handle(protocol.CommandSeal, sealer.Seal)
	}
	var escrow agent.Escrower
	var loader agent.KeyLoader
	var keySync *agent.KeySync
	if cfg.HasCapability(protocol.CapabilityKeys) {
		kmsClient, err := newKMS(cfg, cfg.KMSEscrowKeyID)
		if err != nil {
			return err
		}
		keySync = agent.NewKeySync(agent.KeySyncOptions{
			Kube:        kube,
			Namespace:   cfg.ControllerNamespace,
			Deployment:  cfg.ControllerDeployment,
			KMS:         kmsClient,
			EscrowKeyID: cfg.KMSEscrowKeyID,
			Env:         cfg.EnvName,
			Escrow:      client,
			Logger:      logger,
		})
		escrow, loader = keySync, keySync
		commands.Handle(protocol.CommandKeysRestore, keySync.Restore)
	}
	if cfg.HasCapability(protocol.CapabilityRenewal) {
		renewal := agent.NewRenewal(kube, cfg.ControllerNamespace, cfg.ControllerDeployment, logger)
		commands.Handle(protocol.CommandRenewalEnable, renewal.Enable)
	}
	// cleanup needs keys (config.LoadAgent refuses it alone): it counts with
	// the key Secrets and removes keys as key sync restarts the controller
	var usage *agent.Usage
	var usageReporter agent.UsageReporter
	if cfg.HasCapability(protocol.CapabilityCleanup) {
		sealedSecrets, err := dynamic.NewForConfig(restCfg)
		if err != nil {
			return fmt.Errorf("failed to create kubernetes client: %w", err)
		}
		usage = agent.NewUsage(agent.UsageOptions{
			Kube:          kube,
			SealedSecrets: sealedSecrets,
			Namespace:     cfg.ControllerNamespace,
			Deployment:    cfg.ControllerDeployment,
			Interval:      cfg.KeyUsageInterval,
			Logger:        logger,
		})
		usageReporter = usage // only here: a nil *Usage would make a non-nil interface
		cleanup := agent.NewCleanup(keySync, usage, certs, logger)
		commands.Handle(protocol.CommandKeysDelete, cleanup.Delete)
	}

	a := agent.New(agent.Options{
		Inventory:    inventory,
		ControlPlane: client,
		Interval:     cfg.CheckInInterval,
		Capabilities: cfg.Capabilities,
		Commands:     commands.Types(),
		Escrow:       escrow,
		Loader:       loader,
		Usage:        usageReporter,
		Logger:       logger,
		Version:      version.Version,
	})

	// on SIGTERM the check-in loop stops at once; the command runner finishes
	// the commands in flight within agent.ShutdownGrace, and reports those
	// it could not finish as failed
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.InfoContext(ctx, "starting agent",
		"version", version.Version, "env", cfg.EnvName, "control_plane", cfg.ControlPlaneURL,
		"identity", cfg.IdentityMode, "capabilities", cfg.Capabilities, "commands", commands.Types())
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return a.Run(ctx) })
	g.Go(func() error { return commands.Run(ctx) })
	if usage != nil {
		g.Go(func() error { return usage.Run(ctx) })
	}
	g.Go(func() error { return httpserver.Serve(ctx, cfg.HTTPAddr, a.Handler(), logger) })
	return g.Wait()
}

// newKMS returns the KMS client for a key, in the key's region: the one in
// its ARN, which a key in another account is named by, or else the
// configured region. The transit and escrow keys may be in different
// regions. Credentials come from the SDK's default chain: EKS Pod Identity
// or IRSA in a cluster.
func newKMS(cfg *config.Agent, keyID string) (*kms.Client, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	region := config.KMSKeyRegion(keyID)
	if region == "" {
		region = cfg.KMSRegion
	}
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return nil, errors.New("the seal and keys capabilities need a KMS region: name the keys by ARN, or set APP_KMS_REGION or AWS_REGION")
	}
	return kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		o.Region = region
		if cfg.KMSEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.KMSEndpoint)
		}
	}), nil
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

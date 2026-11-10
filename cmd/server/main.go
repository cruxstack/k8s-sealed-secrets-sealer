// Command server runs the control plane as an HTTP server, for containers
// and local development.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/controlplane"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/webui"
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
	logger := cfg.Logging.Logger(os.Stdout).With("component", "control-plane", "env", cfg.EnvName)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, err := registry.Load(cfg.RegistryFile)
	if err != nil {
		return err
	}
	sessions, err := agentauth.NewSessions(cfg.AgentSessionKey, cfg.PublicURL, cfg.EnvName, nil)
	if err != nil {
		return err
	}
	st, err := newStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	k8sLogins, err := agentauth.NewK8sVerifier(agentauth.K8sOptions{Registry: reg, Audience: cfg.AgentAudience})
	if err != nil {
		return err
	}
	awsLogins, err := agentauth.NewAWSVerifier(agentauth.AWSOptions{
		Registry:     reg,
		Audience:     cfg.AgentAudience,
		AllowedHosts: cfg.AWSSTSHosts,
		Replays:      st,
	})
	if err != nil {
		return err
	}

	userSessions, err := userauth.NewSessions(cfg.UserSessionKey, cfg.PublicURL, cfg.EnvName, cfg.UserSessionTTL, nil)
	if err != nil {
		return err
	}
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions,
		GitHub: userauth.NewGitHub(userauth.GitHubOptions{
			ClientID:     cfg.GitHubOAuthClientID,
			ClientSecret: cfg.GitHubOAuthClientSecret,
			TokenURL:     cfg.GitHubOAuthTokenURL,
			APIURL:       cfg.GitHubAPIURL,
		}),
		PublicURL:    cfg.PublicURL,
		AuthorizeURL: cfg.GitHubURL + "/login/oauth/authorize",
		ClientID:     cfg.GitHubOAuthClientID,
		Env:          cfg.EnvName,
		Org:          cfg.GitHubOrg,
		Teams:        cfg.GitHubAllowedTeams,
		Logger:       logger,
	})

	logger.InfoContext(ctx, "starting control plane",
		"version", version.Version, "agents", len(reg.Agents), "admin_api", cfg.AdminToken != "",
		"github_org", cfg.GitHubOrg, "github_teams", cfg.GitHubAllowedTeams)
	srv := controlplane.New(controlplane.Options{
		Logger:   logger,
		Version:  version.Version,
		Env:      cfg.EnvName,
		Registry: reg,
		Logins: map[string]controlplane.LoginVerifier{
			protocol.MethodK8sOIDC: k8sLogins,
			protocol.MethodAWSSTS:  awsLogins,
		},
		Sessions:   sessions,
		Store:      st,
		AdminToken: cfg.AdminToken,
		Users:      users,
		WebUI:      webui.Handler(),
		HSTS:       strings.HasPrefix(cfg.PublicURL, "https://"),
	})
	return httpserver.Serve(ctx, cfg.HTTPAddr, srv.Handler(), logger)
}

func newStore(ctx context.Context, cfg *config.ControlPlane, logger *slog.Logger) (*store.Dynamo, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		if cfg.DynamoDBEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.DynamoDBEndpoint)
		}
	})
	st := store.NewDynamo(client, cfg.DynamoDBTable)
	if !cfg.DynamoDBCreateTable {
		return st, nil
	}
	// the local emulator may still be starting
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		err := st.EnsureTable(ctx)
		if err == nil {
			logger.InfoContext(ctx, "dynamodb table ready", "table", cfg.DynamoDBTable)
			return st, nil
		}
		logger.WarnContext(ctx, "waiting for dynamodb", "error", err)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("failed to create dynamodb table %s: %w", cfg.DynamoDBTable, err)
		case <-time.After(2 * time.Second):
		}
	}
}

// Package app wires the control plane together from its configuration, the
// same way for every way it runs: as an HTTP server (cmd/server) and as an
// AWS Lambda function (cmd/lambda).
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/config"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/controlplane"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubapp"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/manifest"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/webui"
)

// NewControlPlane returns the control plane's HTTP handler. It makes no
// network calls, except to create the DynamoDB table when the configuration
// asks for it (local emulators only).
func NewControlPlane(ctx context.Context, cfg *config.ControlPlane, logger *slog.Logger) (http.Handler, error) {
	reg, err := loadRegistry(cfg)
	if err != nil {
		return nil, err
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	sessions, err := agentauth.NewSessions(cfg.AgentSessionKey, cfg.PublicURL, cfg.EnvName, nil)
	if err != nil {
		return nil, err
	}
	st, err := newStore(ctx, awsCfg, cfg, logger)
	if err != nil {
		return nil, err
	}
	k8sLogins, err := agentauth.NewK8sVerifier(agentauth.K8sOptions{Registry: reg, Audience: cfg.AgentAudience})
	if err != nil {
		return nil, err
	}
	awsLogins, err := agentauth.NewAWSVerifier(agentauth.AWSOptions{
		Registry:     reg,
		Audience:     cfg.AgentAudience,
		AllowedHosts: cfg.AWSSTSHosts,
		Replays:      st,
	})
	if err != nil {
		return nil, err
	}

	userSessions, err := userauth.NewSessions(cfg.UserSessionKey, cfg.PublicURL, cfg.EnvName, cfg.UserSessionTTL, nil)
	if err != nil {
		return nil, err
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

	githubApp, err := githubapp.New(githubapp.Options{
		APIURL:         cfg.GitHubAPIURL,
		AppID:          cfg.GitHubAppID,
		PrivateKey:     cfg.GitHubAppPrivateKey,
		Org:            cfg.GitHubOrg,
		InstallationID: cfg.GitHubAppInstallationID,
	})
	if err != nil {
		return nil, err
	}
	repoService, err := repos.New(repos.Options{
		GitHub:      githubApp,
		Env:         cfg.EnvName,
		Annotations: manifest.Annotations{Env: cfg.EnvAnnotation, Region: cfg.RegionAnnotation},
		FileGlobs:   cfg.DiscoveryFileGlobs,
		Logger:      logger,
	})
	if err != nil {
		return nil, err
	}

	transit, err := newKMS(awsCfg, cfg)
	if err != nil {
		return nil, err
	}

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
		Repos:      repoService,
		// the control plane only ever generates data keys with it
		Transit:      transit,
		TransitKeyID: cfg.KMSTransitKeyID,
		WebUI:        webui.Handler(),
		HSTS:         strings.HasPrefix(cfg.PublicURL, "https://"),

		KeyRenewPeriod: cfg.KeyRenewPeriod,
	})
	return srv.Handler(), nil
}

// loadRegistry reads the agent registry from its file or, when it is given
// inline (as on Lambda, often from an SSM parameter), from the
// configuration.
func loadRegistry(cfg *config.ControlPlane) (*registry.Registry, error) {
	if cfg.RegistryFile != "" {
		return registry.Load(cfg.RegistryFile)
	}
	reg, err := registry.Parse(cfg.Registry, "")
	if err != nil {
		return nil, fmt.Errorf("failed to read APP_REGISTRY: %w", err)
	}
	return reg, nil
}

// newKMS returns the client for the transit key, as the one thing it may do
// with it: generate data keys. Credentials come from the SDK's default chain.
func newKMS(awsCfg aws.Config, cfg *config.ControlPlane) (envelope.DataKeyGenerator, error) {
	region := cfg.KMSRegion
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return nil, errors.New("sealing needs a KMS region: set APP_KMS_REGION or AWS_REGION")
	}
	return kms.NewFromConfig(awsCfg, func(o *kms.Options) {
		o.Region = region
		if cfg.KMSEndpoint != "" {
			o.BaseEndpoint = aws.String(cfg.KMSEndpoint)
		}
	}), nil
}

func newStore(ctx context.Context, awsCfg aws.Config, cfg *config.ControlPlane, logger *slog.Logger) (*store.Dynamo, error) {
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

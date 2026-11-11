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
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/version"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/webui"
)

// ControlPlane is the control plane for the envs it serves on one URL: their
// HTTP handler, and their ticks, which advance reseal schedules and runs.
type ControlPlane struct {
	http.Handler
	// TickInterval is how often Tick is to be called.
	TickInterval time.Duration
	envs         []*controlplane.Server
	logger       *slog.Logger
}

// NewControlPlane returns the control plane for the envs it serves on one
// URL (config.LoadControlPlanes): one sign-in and web UI for all of them,
// and for each its own registry, store, transit key and agents. It makes no
// network calls, except to create DynamoDB tables when the configuration
// asks for it (local emulators only).
func NewControlPlane(ctx context.Context, cfgs []*config.ControlPlane, logger *slog.Logger) (*ControlPlane, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("no env to serve")
	}
	// settings every env shares come from the first
	shared := cfgs[0]
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}

	userSessions, err := userauth.NewSessions(shared.UserSessionKey, shared.PublicURL, shared.UserSessionTTL, nil)
	if err != nil {
		return nil, err
	}
	policies := make([]userauth.EnvPolicy, len(cfgs))
	for i, cfg := range cfgs {
		policies[i] = userauth.EnvPolicy{Name: cfg.EnvName, Teams: cfg.GitHubAllowedTeams, AdminTeams: cfg.GitHubAdminTeams}
	}
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions,
		GitHub: userauth.NewGitHub(userauth.GitHubOptions{
			ClientID:     shared.GitHubOAuthClientID,
			ClientSecret: shared.GitHubOAuthClientSecret,
			TokenURL:     shared.GitHubOAuthTokenURL,
			APIURL:       shared.GitHubAPIURL,
		}),
		PublicURL:    shared.PublicURL,
		AuthorizeURL: shared.GitHubURL + "/login/oauth/authorize",
		ClientID:     shared.GitHubOAuthClientID,
		Org:          shared.GitHubOrg,
		Envs:         policies,
		Logger:       logger,
	})
	// one GitHub App reads and writes for every env, so the envs share what
	// it learns from GitHub too
	githubApp, err := githubapp.New(githubapp.Options{
		APIURL:         shared.GitHubAPIURL,
		AppID:          shared.GitHubAppID,
		PrivateKey:     shared.GitHubAppPrivateKey,
		Org:            shared.GitHubOrg,
		InstallationID: shared.GitHubAppInstallationID,
		Logger:         logger,
	})
	if err != nil {
		return nil, err
	}
	githubCache := repos.NewCache()

	envs := make([]*controlplane.Server, len(cfgs))
	registries := newEnvRegistries()
	for i, cfg := range cfgs {
		log := logger
		if len(cfgs) > 1 {
			log = logger.With("env", cfg.EnvName)
		}
		if envs[i], err = newEnv(ctx, awsCfg, cfg, users.Env(cfg.EnvName), githubApp, githubCache, registries, log); err != nil {
			return nil, fmt.Errorf("env %s: %w", cfg.EnvName, err)
		}
	}
	logger.InfoContext(ctx, "starting control plane",
		"version", version.Version, "envs", len(cfgs), "github_org", shared.GitHubOrg, "tick_interval", shared.TickInterval.String())
	return &ControlPlane{
		Handler: controlplane.NewHost(controlplane.HostOptions{
			Version: version.Version,
			Users:   users,
			Envs:    envs,
			WebUI:   webui.Handler(),
			HSTS:    strings.HasPrefix(shared.PublicURL, "https://"),
		}),
		TickInterval: shared.TickInterval,
		envs:         envs,
		logger:       logger,
	}, nil
}

// tickTime bounds a tick the ticker starts: ticks advance work a bounded
// step, and one that runs long is followed by the next at once.
const tickTime = 50 * time.Second

// Tick advances every env's reseal schedules and runs once, each env in its
// share of the time ctx leaves, and returns the errors it met.
func (c *ControlPlane) Tick(ctx context.Context) error {
	var errs []error
	for i, env := range c.envs {
		envCtx, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			envCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(c.envs)-i))
		}
		if err := env.Tick(envCtx); err != nil {
			errs = append(errs, fmt.Errorf("env %s: %w", env.Env(), err))
		}
		cancel()
	}
	return errors.Join(errs...)
}

// RunTicker ticks every TickInterval until ctx ends, one tick at a time:
// the container's way to advance reseal schedules and runs. Lambda is
// invoked by a schedule instead (cmd/lambda).
func (c *ControlPlane) RunTicker(ctx context.Context) error {
	t := time.NewTicker(c.TickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		tickCtx, cancel := context.WithTimeout(ctx, tickTime)
		if err := c.Tick(tickCtx); err != nil && ctx.Err() == nil {
			c.logger.ErrorContext(ctx, "reseal tick failed", "event", "reseal.tick_failed", "error", err)
		}
		cancel()
	}
}

// newEnv returns one env's server. Its registry must not register an
// identity that another env in registries does.
func newEnv(ctx context.Context, awsCfg aws.Config, cfg *config.ControlPlane, users controlplane.UserGuard, githubApp *githubapp.Client, githubCache *repos.Cache, registries *envRegistries, logger *slog.Logger) (*controlplane.Server, error) {
	sessions, err := agentauth.NewSessions(cfg.AgentSessionKey, cfg.PublicURL, cfg.EnvName, nil)
	if err != nil {
		return nil, err
	}
	st, err := newStore(ctx, awsCfg, cfg, logger)
	if err != nil {
		return nil, err
	}
	agents := &envRegistry{
		env: cfg.EnvName,
		cfg: cfg,
		logins: &envLogins{
			audience: cfg.AgentAudience,
			stsHosts: cfg.AWSSTSHosts,
			replays:  st,
			stsLimit: agentauth.NewSTSLimiter(),
		},
		all: registries,
	}
	reg, logins, err := agents.start(ctx)
	if err != nil {
		return nil, err
	}
	// a registry in a file or an SSM parameter is read again while the
	// control plane runs, so removing an agent revokes it without a restart
	var reload func(context.Context) (*registry.Registry, map[string]controlplane.LoginVerifier, error)
	if agents.reloadable() {
		reload = agents.reload
	}
	repoService, err := repos.New(repos.Options{
		GitHub:      githubApp,
		Env:         cfg.EnvName,
		Annotations: manifest.Annotations{Env: cfg.EnvAnnotation, Region: cfg.RegionAnnotation},
		FileGlobs:   cfg.DiscoveryFileGlobs,
		Cache:       githubCache,
		Logger:      logger,
	})
	if err != nil {
		return nil, err
	}
	transit, err := newKMS(awsCfg, cfg)
	if err != nil {
		return nil, err
	}

	// the logger names the env
	logger.InfoContext(ctx, "serving env",
		"agents", len(reg.Agents), "registry_reload", reload != nil, "admin_api", cfg.AdminToken != "",
		"admin_token_key_changes", cfg.AdminTokenKeyChanges,
		"github_teams", cfg.GitHubAllowedTeams, "github_admin_teams", cfg.GitHubAdminTeams)
	return controlplane.New(controlplane.Options{
		Logger:         logger,
		Version:        version.Version,
		Env:            cfg.EnvName,
		Registry:       reg,
		Logins:         logins,
		ReloadRegistry: reload,
		Sessions:       sessions,
		Store:          st,
		AdminToken:     cfg.AdminToken,
		Users:          users,
		Repos:          repoService,
		// the control plane only ever generates data keys with it
		Transit:      transit,
		TransitKeyID: cfg.KMSTransitKeyID,
		HSTS:         strings.HasPrefix(cfg.PublicURL, "https://"),

		KeyRenewPeriod: cfg.KeyRenewPeriod,
		TickInterval:   cfg.TickInterval,

		AdminTokenKeyChanges: cfg.AdminTokenKeyChanges,
	}), nil
}

// newKMS returns the client for the transit key, as the one thing it may do
// with it: generate data keys. It calls the key's region: the one in its
// ARN, which a key in another account is named by, or else the configured
// region. Credentials come from the SDK's default chain.
func newKMS(awsCfg aws.Config, cfg *config.ControlPlane) (envelope.DataKeyGenerator, error) {
	region := config.KMSKeyRegion(cfg.KMSTransitKeyID)
	if region == "" {
		region = cfg.KMSRegion
	}
	if region == "" {
		region = awsCfg.Region
	}
	if region == "" {
		return nil, errors.New("sealing needs a KMS region: name the transit key by its ARN, or set APP_KMS_REGION or AWS_REGION")
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

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
	"sync"
	"sync/atomic"
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
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/githubsetup"
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
//
// With the GitHub App's credentials in an SSM parameter
// (APP_GITHUB_APP_PARAMETER) that does not exist yet, it starts in setup
// mode: agents check in as usual, and people see only the setup page,
// which creates the App and writes the parameter. It then serves with the
// new App, as other instances do once they read the parameter.
type ControlPlane struct {
	// TickInterval is how often Tick is to be called.
	TickInterval time.Duration

	cfgs    []*config.ControlPlane
	awsCfg  aws.Config
	logger  *slog.Logger
	current atomic.Pointer[instance]
	// stores are each env's table, kept when the App is set up and the
	// envs are built again; build adds to it, under setupMu or alone
	stores map[string]*store.Dynamo

	// setup is where the App's credentials are stored; nil when the
	// settings hold them
	setup githubsetup.Store
	// setupMu is held while the parameter is read or the App put to use
	setupMu    sync.Mutex
	configured atomic.Bool
	// nextCheck is when a request next reads the parameter, in Unix
	// nanoseconds, while the App is not set up
	nextCheck atomic.Int64
}

// instance is what serves at one time: the handler, and the envs it ticks.
type instance struct {
	http.Handler
	envs []*controlplane.Server
}

// setUpCheckInterval is how often an instance in setup mode reads the
// GitHub App's parameter, as requests come in, to learn that another
// instance set the App up.
const setUpCheckInterval = 10 * time.Second

// NewControlPlane returns the control plane for the envs it serves on one
// URL (config.LoadControlPlanes): one sign-in and web UI for all of them,
// and for each its own registry, store, transit key and agents. It makes no
// network calls, except to read the GitHub App's parameter when the
// configuration names one, and to create DynamoDB tables when it asks for
// it (local emulators only).
func NewControlPlane(ctx context.Context, cfgs []*config.ControlPlane, logger *slog.Logger) (*ControlPlane, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("no env to serve")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws configuration: %w", err)
	}
	var appStore githubsetup.Store
	if arn := cfgs[0].GitHubAppParameter; arn != "" {
		if appStore, err = githubsetup.NewSSMStore(awsCfg, arn, cfgs[0].SSMEndpoint); err != nil {
			return nil, err
		}
	}
	return newControlPlane(ctx, cfgs, awsCfg, appStore, logger)
}

// newControlPlane is NewControlPlane with the GitHub App's credentials in
// appStore, or in the settings when appStore is nil.
func newControlPlane(ctx context.Context, cfgs []*config.ControlPlane, awsCfg aws.Config, appStore githubsetup.Store, logger *slog.Logger) (*ControlPlane, error) {
	// settings every env shares come from the first
	shared := cfgs[0]
	c := &ControlPlane{
		TickInterval: shared.TickInterval, cfgs: cfgs, awsCfg: awsCfg, logger: logger,
		setup: appStore, stores: map[string]*store.Dynamo{},
	}
	logger.InfoContext(ctx, "starting control plane",
		"version", version.Version, "envs", len(cfgs), "github_org", shared.GitHubOrg, "tick_interval", shared.TickInterval.String())

	if appStore == nil {
		inst, err := c.build(ctx, cfgs, nil)
		if err != nil {
			return nil, err
		}
		c.current.Store(inst)
		c.configured.Store(true)
		return c, nil
	}

	loadCtx, cancel := context.WithTimeout(ctx, setUpReadTimeout)
	defer cancel()
	creds, err := appStore.Load(loadCtx)
	switch {
	case err == nil:
		if err := c.configureLocked(ctx, creds); err != nil {
			return nil, err
		}
		return c, nil
	case !errors.Is(err, githubsetup.ErrNotSetUp):
		return nil, err
	}

	setup := githubsetup.New(githubsetup.Options{
		Store:     appStore,
		Org:       shared.GitHubOrg,
		PublicURL: shared.PublicURL,
		GitHubURL: shared.GitHubURL,
		APIURL:    shared.GitHubAPIURL,
		OnCreated: c.configure,
		Logger:    logger,
	})
	inst, err := c.build(ctx, cfgs, setup)
	if err != nil {
		return nil, err
	}
	c.current.Store(inst)
	c.nextCheck.Store(time.Now().Add(setUpCheckInterval).UnixNano())
	logger.WarnContext(ctx, "the github app is not set up: an owner of the org sets it up at "+strings.TrimSuffix(shared.PublicURL, "/")+"/setup",
		"event", "github_app.setup_needed", "github_org", shared.GitHubOrg, "parameter", shared.GitHubAppParameter)
	return c, nil
}

// setUpReadTimeout bounds reading the GitHub App's parameter.
const setUpReadTimeout = 15 * time.Second

// ServeHTTP serves with the current instance. While the GitHub App is not
// set up, it first reads its parameter if it has not lately, so an instance
// learns that another set the App up.
func (c *ControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.configured.Load() {
		c.checkSetUp(r.Context())
	}
	c.current.Load().ServeHTTP(w, r)
}

// checkSetUp reads the GitHub App's parameter, at most once every
// setUpCheckInterval and never while another request does, and starts
// using the App once it is there.
func (c *ControlPlane) checkSetUp(ctx context.Context) {
	if time.Now().UnixNano() < c.nextCheck.Load() || !c.setupMu.TryLock() {
		return
	}
	defer c.setupMu.Unlock()
	if c.configured.Load() {
		return
	}
	c.nextCheck.Store(time.Now().Add(setUpCheckInterval).UnixNano())
	// the request may end first; reading and building must not
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), setUpReadTimeout)
	defer cancel()
	creds, err := c.setup.Load(ctx)
	switch {
	case errors.Is(err, githubsetup.ErrNotSetUp):
		return
	case err != nil:
		c.logger.WarnContext(ctx, "failed to read the github app's parameter", "error", err)
		return
	}
	if err := c.configureLocked(ctx, creds); err != nil {
		c.logger.ErrorContext(ctx, "failed to start using the github app", "app_id", creds.AppID, "error", err)
	}
}

// configure starts using a GitHub App the setup page created.
func (c *ControlPlane) configure(ctx context.Context, creds githubsetup.Credentials) error {
	c.setupMu.Lock()
	defer c.setupMu.Unlock()
	return c.configureLocked(ctx, creds)
}

// configureLocked builds the control plane with the App's credentials and
// serves with it from then on. The caller holds setupMu, or is the only
// goroutine yet.
func (c *ControlPlane) configureLocked(ctx context.Context, creds githubsetup.Credentials) error {
	if c.configured.Load() {
		return nil
	}
	cfgs := make([]*config.ControlPlane, len(c.cfgs))
	for i, cfg := range c.cfgs {
		withApp := *cfg
		withApp.GitHubAppID = creds.AppID
		withApp.GitHubAppPrivateKey = []byte(creds.PrivateKey)
		withApp.GitHubOAuthClientID = creds.ClientID
		withApp.GitHubOAuthClientSecret = creds.ClientSecret
		cfgs[i] = &withApp
	}
	inst, err := c.build(ctx, cfgs, nil)
	if err != nil {
		return err
	}
	c.current.Store(inst)
	c.configured.Store(true)
	c.logger.InfoContext(ctx, "serving with the github app from its parameter", "app_id", creds.AppID, "app_slug", creds.Slug)
	return nil
}

// build returns what serves the envs: with the GitHub App the settings in
// cfgs name or, given setup, without one, serving the setup page and the
// agents.
func (c *ControlPlane) build(ctx context.Context, cfgs []*config.ControlPlane, setup *githubsetup.Handler) (*instance, error) {
	shared := cfgs[0]
	var gh *envGitHub
	var users *userauth.Handler
	if setup == nil {
		userSessions, err := userauth.NewSessions(shared.UserSessionKey, shared.PublicURL, shared.UserSessionTTL, nil)
		if err != nil {
			return nil, err
		}
		policies := make([]userauth.EnvPolicy, len(cfgs))
		for i, cfg := range cfgs {
			policies[i] = userauth.EnvPolicy{Name: cfg.EnvName, Teams: cfg.GitHubAllowedTeams, AdminTeams: cfg.GitHubAdminTeams}
		}
		users = userauth.NewHandler(userauth.HandlerOptions{
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
			Logger:       c.logger,
		})
		// one GitHub App reads and writes for every env, so the envs share
		// what it learns from GitHub too
		app, err := githubapp.New(githubapp.Options{
			APIURL:         shared.GitHubAPIURL,
			AppID:          shared.GitHubAppID,
			PrivateKey:     shared.GitHubAppPrivateKey,
			Org:            shared.GitHubOrg,
			InstallationID: shared.GitHubAppInstallationID,
			Logger:         c.logger,
		})
		if err != nil {
			return nil, err
		}
		gh = &envGitHub{users: users, app: app, cache: repos.NewCache()}
	}

	envs := make([]*controlplane.Server, len(cfgs))
	registries := newEnvRegistries()
	for i, cfg := range cfgs {
		log := c.logger
		if len(cfgs) > 1 {
			log = c.logger.With("env", cfg.EnvName)
		}
		st, ok := c.stores[cfg.EnvName]
		if !ok {
			var err error
			if st, err = newStore(ctx, c.awsCfg, cfg, log); err != nil {
				return nil, fmt.Errorf("env %s: %w", cfg.EnvName, err)
			}
			c.stores[cfg.EnvName] = st
		}
		var err error
		if envs[i], err = newEnv(ctx, c.awsCfg, cfg, st, gh, registries, log); err != nil {
			return nil, fmt.Errorf("env %s: %w", cfg.EnvName, err)
		}
	}
	host := controlplane.HostOptions{
		Version: version.Version,
		Envs:    envs,
		WebUI:   webui.Handler(),
		HSTS:    strings.HasPrefix(shared.PublicURL, "https://"),
	}
	if setup != nil {
		host.Setup, host.SetupFormAction = setup, setup.FormAction()
	} else {
		host.Users = users
	}
	return &instance{Handler: controlplane.NewHost(host), envs: envs}, nil
}

// envGitHub is what an env reaches GitHub with: sign-in, and the GitHub App
// every env shares with its cache.
type envGitHub struct {
	users *userauth.Handler
	app   *githubapp.Client
	cache *repos.Cache
}

// tickTime bounds a tick the ticker starts: ticks advance work a bounded
// step, and one that runs long is followed by the next at once.
const tickTime = 50 * time.Second

// Tick advances every env's reseal schedules and runs once, each env in its
// share of the time ctx leaves, and returns the errors it met. Until the
// GitHub App is set up there is nothing to advance.
func (c *ControlPlane) Tick(ctx context.Context) error {
	var errs []error
	envs := c.current.Load().envs
	for i, env := range envs {
		envCtx, cancel := ctx, context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			envCtx, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(envs)-i))
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

// newEnv returns one env's server: with gh, its user and repository APIs,
// and without it only the agent and admin APIs. Its registry must not
// register an identity that another env in registries does.
func newEnv(ctx context.Context, awsCfg aws.Config, cfg *config.ControlPlane, st *store.Dynamo, gh *envGitHub, registries *envRegistries, logger *slog.Logger) (*controlplane.Server, error) {
	sessions, err := agentauth.NewSessions(cfg.AgentSessionKey, cfg.PublicURL, cfg.EnvName, nil)
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
	// a nil *userauth.EnvGuard in the interface would not read as nil
	var users controlplane.UserGuard
	var repoService *repos.Service
	if gh != nil {
		users = gh.users.Env(cfg.EnvName)
		if repoService, err = repos.New(repos.Options{
			GitHub:      gh.app,
			Env:         cfg.EnvName,
			Annotations: manifest.Annotations{Env: cfg.EnvAnnotation, Region: cfg.RegionAnnotation},
			FileGlobs:   cfg.DiscoveryFileGlobs,
			Cache:       gh.cache,
			Logger:      logger,
		}); err != nil {
			return nil, err
		}
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

		KeyRenewPeriod:   cfg.KeyRenewPeriod,
		TickInterval:     cfg.TickInterval,
		KeyCommandSettle: cfg.KeyCommandSettle,

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

// Package config reads and validates the configuration of the control plane
// and the agent. It is the only package that reads the environment, except
// that the AWS SDK reads its own standard variables (credentials, region).
//
// Any of the control plane's APP_ settings may instead hold the ARN of an
// SSM Parameter Store parameter, whose value is read at start. On Lambda
// this keeps secrets out of environment variables, and lets the agent
// registry be larger than environment variables allow. The registry's
// parameter is read again while the control plane runs.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// Minimum lengths of secrets in the configuration.
const (
	MinSessionKeyBytes = 32
	MinAdminTokenBytes = 32
)

// DefaultTokenFile is where the agent chart mounts the projected
// service-account token the agent logs in with.
const DefaultTokenFile = "/var/run/secrets/k8s-sealed-secrets-sealer/token"

// lookupFunc returns an environment variable's value and whether it is set.
type lookupFunc func(key string) (string, bool)

// Logging configures the process logger.
type Logging struct {
	Level  slog.Level
	Format string // "json" or "text"
}

// Logger returns a logger that writes to w in the configured format.
func (l Logging) Logger(w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: l.Level}
	if l.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// ControlPlane is the control plane's configuration.
type ControlPlane struct {
	HTTPAddr string
	Logging  Logging

	// EnvName is the env this control plane serves, e.g. "dev".
	EnvName string
	// PublicURL is the control plane's external URL. It names this control
	// plane in agent session tokens.
	PublicURL string
	// AgentAudience is the aud claim agent login tokens must carry; it
	// defaults to PublicURL.
	AgentAudience string
	// RegistryFile is the agent registry (see internal/registry). Registry
	// holds it inline instead; exactly one of the two is set.
	RegistryFile string
	Registry     []byte
	// RegistryParameter is the ARN of the SSM parameter Registry was read
	// from, if it was. The control plane reads a registry file or parameter
	// again to pick up changes; an inline one only changes with a restart.
	RegistryParameter string
	// AgentSessionKey signs agent session tokens.
	AgentSessionKey []byte
	// AdminToken enables the admin API when set. With APP_ENVS, an env may
	// have its own instead of the shared one.
	AdminToken string
	// AdminTokenKeyChanges lets the admin token revoke and reinstate keys;
	// without it, the token only reads the fleet. With APP_ENVS, each env
	// sets it for itself.
	AdminTokenKeyChanges bool

	DynamoDBTable string
	// DynamoDBEndpoint overrides the DynamoDB endpoint, for local emulators.
	DynamoDBEndpoint string
	// DynamoDBCreateTable creates the table at startup. Local emulators only.
	DynamoDBCreateTable bool

	// AWSSTSHosts, when set, replaces the default STS hosts agents' signed
	// login requests may target.
	AWSSTSHosts []string

	// GitHub sign-in. GitHubURL is the web host (the authorize page users
	// are sent to); GitHubAPIURL and GitHubOAuthTokenURL are called by the
	// control plane. AllowInsecureGitHub permits http, for local mocks only.
	GitHubURL           string
	GitHubAPIURL        string
	GitHubOAuthTokenURL string
	AllowInsecureGitHub bool
	GitHubOrg           string
	GitHubAllowedTeams  []string
	// GitHubAdminTeams are teams whose members are admins and may see the
	// fleet; empty means nobody is.
	GitHubAdminTeams        []string
	GitHubOAuthClientID     string
	GitHubOAuthClientSecret string
	// UserSessionKey signs user session cookies; UserSessionTTL is their
	// lifetime.
	UserSessionKey []byte
	UserSessionTTL time.Duration

	// The GitHub App that reads repositories and opens pull requests: its
	// ID, private key (PEM) and, optionally, its installation on GitHubOrg
	// (looked up when zero).
	GitHubAppID             string
	GitHubAppPrivateKey     []byte
	GitHubAppInstallationID int64
	// EnvAnnotation and RegionAnnotation are the annotation keys that place
	// a SealedSecret document in an env and a region.
	EnvAnnotation    string
	RegionAnnotation string
	// DiscoveryFileGlobs select the files read when looking for
	// SealedSecrets; empty means the default.
	DiscoveryFileGlobs []string

	// KeyRenewPeriod is the period the control plane asks a controller to
	// renew its key with, when no cluster in the env renews.
	KeyRenewPeriod time.Duration

	// KMSTransitKeyID is the KMS key (ID, ARN or alias) values are encrypted
	// under on their way to an agent. The control plane only generates data
	// keys with it; agents decrypt.
	KMSTransitKeyID string
	// KMSRegion is the region of the KMS endpoint for a transit key not
	// named by ARN. A key named by its ARN (as a key in another account must
	// be) is called in the ARN's region. Empty uses the AWS SDK's region.
	KMSRegion string
	// KMSEndpoint overrides the KMS endpoint, for local emulators.
	KMSEndpoint string
}

// Agent is the agent's configuration.
type Agent struct {
	HTTPAddr string
	Logging  Logging

	// KubeContext selects a kubeconfig context when the agent runs outside a
	// cluster. Empty means the in-cluster configuration.
	KubeContext string

	// ControllerNamespace, ControllerName and ControllerDeployment locate the
	// sealed-secrets controller's Service and Deployment.
	ControllerNamespace  string
	ControllerName       string
	ControllerDeployment string

	// ControlPlaneURL is where the agent checks in. It must be https unless
	// AllowInsecureControlPlane is set, which is for local stacks only.
	ControlPlaneURL           string
	AllowInsecureControlPlane bool
	// IdentityMode is how the agent logs in: protocol.MethodK8sOIDC (a
	// projected service-account token) or protocol.MethodAWSSTS (its IAM
	// role, via a signed sts:GetCallerIdentity request).
	IdentityMode string
	// IdentityAudience names the control plane in the signed AWS request.
	IdentityAudience string
	// AWSSTSRegion selects the regional STS endpoint to sign for; empty uses
	// the AWS SDK's region.
	AWSSTSRegion string
	// TokenFile holds the projected service-account token to log in with.
	TokenFile string
	// Capabilities are the capabilities this agent's Helm values enabled.
	Capabilities []string
	// CheckInInterval is how often the agent reports to the control plane.
	CheckInInterval time.Duration
	// EnvName is the env this agent belongs to. The agent refuses a control
	// plane serving another env, and binds escrowed keys to it.
	EnvName string
	// KMSEscrowKeyID is the KMS key (ID, ARN or alias) escrowed sealing keys
	// are encrypted under. Required with the keys capability.
	KMSEscrowKeyID string
	// KMSTransitKeyID is the KMS key values to seal arrive encrypted under.
	// Required with the seal capability.
	KMSTransitKeyID string
	// KMSRegion is the region of the KMS endpoint for keys not named by ARN.
	// A key named by its ARN (as a key in another account must be) is
	// called in the ARN's region, so the transit and escrow keys may be in
	// different regions. Empty uses the AWS SDK's region.
	KMSRegion string
	// KMSEndpoint overrides the KMS endpoint, for local emulators.
	KMSEndpoint string
}

// HasCapability reports whether the agent has capability c.
func (a *Agent) HasCapability(c string) bool { return slices.Contains(a.Capabilities, c) }

// LoadAgent reads the agent's configuration from the environment and reports
// every invalid setting at once.
func LoadAgent() (*Agent, error) {
	return loadAgent(os.LookupEnv)
}

func loadControlPlane(lookup lookupFunc) (*ControlPlane, error) {
	r := &reader{lookup: lookup}
	cfg := &ControlPlane{
		HTTPAddr:            r.str("APP_HTTP_ADDR", ":8080"),
		Logging:             r.logging(),
		EnvName:             r.required(r.dnsLabel("APP_ENV_NAME", ""), "APP_ENV_NAME"),
		PublicURL:           r.required(r.url("APP_PUBLIC_URL", true), "APP_PUBLIC_URL"),
		RegistryFile:        r.str("APP_REGISTRY_FILE", ""),
		Registry:            []byte(r.str("APP_REGISTRY", "")),
		AgentSessionKey:     []byte(r.secret("APP_AGENT_SESSION_KEY", MinSessionKeyBytes, true)),
		AdminToken:          r.secret("APP_ADMIN_TOKEN", MinAdminTokenBytes, false),
		DynamoDBTable:       r.required(r.str("APP_DYNAMODB_TABLE", ""), "APP_DYNAMODB_TABLE"),
		DynamoDBEndpoint:    r.url("APP_DYNAMODB_ENDPOINT", true),
		DynamoDBCreateTable: r.boolean("APP_DYNAMODB_CREATE_TABLE", false),
	}
	cfg.AgentAudience = r.str("APP_AGENT_AUDIENCE", cfg.PublicURL)
	// a shared token, often given to monitoring, changes keys only where an
	// env allows it
	cfg.AdminTokenKeyChanges = r.boolean("APP_ADMIN_TOKEN_KEY_CHANGES", false)
	if (cfg.RegistryFile == "") == (len(cfg.Registry) == 0) {
		r.fail("set exactly one of APP_REGISTRY_FILE and APP_REGISTRY (the registry inline)")
	}
	if cfg.AdminTokenKeyChanges && cfg.AdminToken == "" {
		r.fail("APP_ADMIN_TOKEN_KEY_CHANGES (adminTokenKeyChanges) needs an admin token")
	}

	cfg.AllowInsecureGitHub = r.boolean("APP_ALLOW_INSECURE_GITHUB", false)
	cfg.GitHubURL = r.url("APP_GITHUB_URL", cfg.AllowInsecureGitHub)
	if cfg.GitHubURL == "" {
		cfg.GitHubURL = "https://github.com"
	}
	cfg.GitHubAPIURL = r.url("APP_GITHUB_API_URL", cfg.AllowInsecureGitHub)
	if cfg.GitHubAPIURL == "" {
		cfg.GitHubAPIURL = "https://api.github.com"
	}
	cfg.GitHubOAuthTokenURL = r.url("APP_GITHUB_OAUTH_TOKEN_URL", cfg.AllowInsecureGitHub)
	if cfg.GitHubOAuthTokenURL == "" {
		cfg.GitHubOAuthTokenURL = cfg.GitHubURL + "/login/oauth/access_token"
	}
	cfg.GitHubOrg = r.required(r.str("APP_GITHUB_ORG", ""), "APP_GITHUB_ORG")
	for _, team := range strings.Split(r.str("APP_GITHUB_ALLOWED_TEAMS", ""), ",") {
		if team = strings.TrimSpace(team); team != "" {
			cfg.GitHubAllowedTeams = append(cfg.GitHubAllowedTeams, team)
		}
	}
	for _, team := range strings.Split(r.str("APP_GITHUB_ADMIN_TEAMS", ""), ",") {
		if team = strings.TrimSpace(team); team != "" {
			cfg.GitHubAdminTeams = append(cfg.GitHubAdminTeams, team)
		}
	}
	cfg.GitHubOAuthClientID = r.required(r.str("APP_GITHUB_OAUTH_CLIENT_ID", ""), "APP_GITHUB_OAUTH_CLIENT_ID")
	cfg.GitHubOAuthClientSecret = r.secret("APP_GITHUB_OAUTH_CLIENT_SECRET", 1, true)
	cfg.UserSessionKey = []byte(r.secret("APP_USER_SESSION_KEY", MinSessionKeyBytes, true))
	cfg.UserSessionTTL = r.duration("APP_USER_SESSION_TTL", 8*time.Hour, 15*time.Minute, 24*time.Hour)
	cfg.GitHubAppID = r.required(r.str("APP_GITHUB_APP_ID", ""), "APP_GITHUB_APP_ID")
	cfg.GitHubAppPrivateKey = []byte(r.secret("APP_GITHUB_APP_PRIVATE_KEY", 1, true))
	if len(cfg.GitHubAppPrivateKey) > 0 && !strings.Contains(string(cfg.GitHubAppPrivateKey), "PRIVATE KEY-----") {
		r.fail("APP_GITHUB_APP_PRIVATE_KEY must be a PEM private key")
	}
	cfg.GitHubAppInstallationID = r.integer("APP_GITHUB_APP_INSTALLATION_ID", 0)
	cfg.EnvAnnotation = r.qualifiedName("APP_ENV_ANNOTATION", "k8s-sealed-secrets-sealer/env")
	cfg.RegionAnnotation = r.qualifiedName("APP_REGION_ANNOTATION", "k8s-sealed-secrets-sealer/region")
	for _, g := range strings.Split(r.str("APP_DISCOVERY_FILE_GLOBS", ""), ",") {
		if g = strings.TrimSpace(g); g == "" {
			continue
		}
		if _, err := path.Match(g, ""); err != nil {
			r.fail("APP_DISCOVERY_FILE_GLOBS: %q is not a valid glob", g)
			continue
		}
		cfg.DiscoveryFileGlobs = append(cfg.DiscoveryFileGlobs, g)
	}
	cfg.KeyRenewPeriod = r.duration("APP_KEY_RENEW_PERIOD", 720*time.Hour, time.Hour, 365*24*time.Hour)
	cfg.KMSTransitKeyID = r.required(r.str("APP_KMS_TRANSIT_KEY_ID", ""), "APP_KMS_TRANSIT_KEY_ID")
	cfg.KMSRegion = r.str("APP_KMS_REGION", "")
	// local emulators only; the endpoint carries no credentials
	cfg.KMSEndpoint = r.url("APP_KMS_ENDPOINT", true)
	for _, h := range strings.Split(r.str("APP_AWS_STS_HOSTS", ""), ",") {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if strings.ContainsAny(h, "/?#@ ") {
			r.fail("APP_AWS_STS_HOSTS: %q must be a host name, optionally with a port", h)
			continue
		}
		cfg.AWSSTSHosts = append(cfg.AWSSTSHosts, h)
	}
	if cfg.DynamoDBCreateTable && cfg.DynamoDBEndpoint == "" {
		r.fail("APP_DYNAMODB_CREATE_TABLE is only for local emulators and requires APP_DYNAMODB_ENDPOINT")
	}
	return cfg, r.err()
}

func loadAgent(lookup lookupFunc) (*Agent, error) {
	r := &reader{lookup: lookup}
	cfg := &Agent{
		HTTPAddr:                  r.str("APP_HTTP_ADDR", ":8081"),
		Logging:                   r.logging(),
		KubeContext:               r.str("APP_KUBE_CONTEXT", ""),
		ControllerNamespace:       r.required(r.dnsLabel("APP_CONTROLLER_NAMESPACE", ""), "APP_CONTROLLER_NAMESPACE"),
		ControllerName:            r.dnsLabel("APP_CONTROLLER_NAME", "sealed-secrets-controller"),
		AllowInsecureControlPlane: r.boolean("APP_ALLOW_INSECURE_CONTROL_PLANE", false),
		TokenFile:                 r.str("APP_IDENTITY_TOKEN_FILE", DefaultTokenFile),
		CheckInInterval:           r.duration("APP_CHECKIN_INTERVAL", 15*time.Second, protocol.MinCheckInInterval, protocol.MaxCheckInInterval),
	}
	cfg.ControllerDeployment = r.dnsSubdomain("APP_CONTROLLER_DEPLOYMENT", cfg.ControllerName)
	cfg.ControlPlaneURL = r.required(r.url("APP_CONTROL_PLANE_URL", cfg.AllowInsecureControlPlane), "APP_CONTROL_PLANE_URL")
	cfg.IdentityAudience = r.str("APP_IDENTITY_AUDIENCE", cfg.ControlPlaneURL)
	cfg.AWSSTSRegion = r.str("APP_AWS_STS_REGION", "")
	switch cfg.IdentityMode = r.str("APP_IDENTITY_MODE", protocol.MethodK8sOIDC); cfg.IdentityMode {
	case protocol.MethodK8sOIDC, protocol.MethodAWSSTS:
	default:
		r.fail("APP_IDENTITY_MODE must be %s or %s: %q", protocol.MethodK8sOIDC, protocol.MethodAWSSTS, cfg.IdentityMode)
	}
	cfg.Capabilities = r.capabilities("APP_CAPABILITIES")
	cfg.EnvName = r.required(r.dnsLabel("APP_ENV_NAME", ""), "APP_ENV_NAME")
	cfg.KMSEscrowKeyID = r.str("APP_KMS_ESCROW_KEY_ID", "")
	if cfg.HasCapability(protocol.CapabilityKeys) && cfg.KMSEscrowKeyID == "" {
		r.fail("APP_KMS_ESCROW_KEY_ID is required with the keys capability")
	}
	cfg.KMSTransitKeyID = r.str("APP_KMS_TRANSIT_KEY_ID", "")
	if cfg.HasCapability(protocol.CapabilitySeal) && cfg.KMSTransitKeyID == "" {
		r.fail("APP_KMS_TRANSIT_KEY_ID is required with the seal capability")
	}
	cfg.KMSRegion = r.str("APP_KMS_REGION", "")
	// local emulators only; the endpoint carries no credentials
	cfg.KMSEndpoint = r.url("APP_KMS_ENDPOINT", true)
	return cfg, r.err()
}

// reader collects every configuration problem so they can be reported
// together instead of one per restart.
type reader struct {
	lookup lookupFunc
	errs   []error
}

func (r *reader) fail(format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf(format, args...))
}

func (r *reader) err() error {
	if len(r.errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration: %w", errors.Join(r.errs...))
}

func (r *reader) str(key, fallback string) string {
	if v, ok := r.lookup(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

func (r *reader) required(v, key string) string {
	if v == "" {
		r.fail("%s is required", key)
	}
	return v
}

// capabilities reads an agent's capabilities: a list, or "none" (or empty)
// for none. An agent with none still checks in, reporting its controller's
// active key. Unset, the agent seals.
func (r *reader) capabilities(key string) []string {
	v, set := r.lookup(key)
	if !set {
		return []string{protocol.CapabilitySeal}
	}
	if v = strings.TrimSpace(v); v == "none" {
		return nil
	}
	var out []string
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		switch {
		case c == "":
		case c == "none":
			r.fail("%s: none cannot be combined with capabilities", key)
		case !protocol.IsCapability(c):
			r.fail("%s: unknown capability %q", key, c)
		case !slices.Contains(out, c):
			out = append(out, c)
		}
	}
	return out
}

func (r *reader) dnsLabel(key, fallback string) string {
	v := r.str(key, fallback)
	if v == "" {
		return ""
	}
	if msgs := validation.IsDNS1123Label(v); len(msgs) > 0 {
		r.fail("%s must be a DNS-1123 label: %s", key, strings.Join(msgs, "; "))
	}
	return v
}

// dnsSubdomain reads a Kubernetes object name that may contain dots, such as
// a Deployment's.
func (r *reader) dnsSubdomain(key, fallback string) string {
	v := r.str(key, fallback)
	if v == "" {
		return ""
	}
	if msgs := validation.IsDNS1123Subdomain(v); len(msgs) > 0 {
		r.fail("%s must be a DNS-1123 subdomain: %s", key, strings.Join(msgs, "; "))
	}
	return v
}

// url reads an absolute URL. Plain http is accepted only when allowHTTP is
// set; otherwise the URL must be https.
func (r *reader) url(key string, allowHTTP bool) string {
	v := r.str(key, "")
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !allowHTTP)) {
		if allowHTTP {
			r.fail("%s must be an absolute http(s) URL", key)
		} else {
			r.fail("%s must be an absolute https URL", key)
		}
		return v
	}
	return strings.TrimSuffix(v, "/")
}

// secret reads a secret value of at least minBytes. The value never appears
// in errors.
func (r *reader) secret(key string, minBytes int, required bool) string {
	v, _ := r.lookup(key)
	switch {
	case v == "" && required:
		r.fail("%s is required", key)
	case v != "" && len(v) < minBytes:
		r.fail("%s must be at least %d bytes", key, minBytes)
	}
	return v
}

// boolean reads true or false. Every flag so far defaults to false, which
// unparam notices; the fallback stays for one that will not.
func (r *reader) boolean(key string, fallback bool) bool { //nolint:unparam // see above
	v := r.str(key, "")
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		r.fail("%s must be true or false: %q", key, v)
		return fallback
	}
	return b
}

// integer reads a non-negative integer.
func (r *reader) integer(key string, fallback int64) int64 {
	v := r.str(key, "")
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		r.fail("%s must be a non-negative whole number: %q", key, v)
		return fallback
	}
	return n
}

// qualifiedName reads a Kubernetes annotation key.
func (r *reader) qualifiedName(key, fallback string) string {
	v := r.str(key, fallback)
	if msgs := validation.IsQualifiedName(v); len(msgs) > 0 {
		r.fail("%s must be an annotation key: %s", key, strings.Join(msgs, "; "))
	}
	return v
}

func (r *reader) duration(key string, fallback, minimum, maximum time.Duration) time.Duration {
	v := r.str(key, "")
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		r.fail("%s must be a duration such as 30s or 5m: %q", key, v)
		return fallback
	}
	if d < minimum || d > maximum {
		r.fail("%s must be between %s and %s: %s", key, minimum, maximum, d)
		return fallback
	}
	return d
}

func (r *reader) logging() Logging {
	l := Logging{Format: "json"}
	switch v := strings.ToLower(r.str("APP_LOG_LEVEL", "info")); v {
	case "debug":
		l.Level = slog.LevelDebug
	case "info":
		l.Level = slog.LevelInfo
	case "warn":
		l.Level = slog.LevelWarn
	case "error":
		l.Level = slog.LevelError
	default:
		r.fail("APP_LOG_LEVEL must be debug, info, warn or error: %q", v)
	}
	switch v := strings.ToLower(r.str("APP_LOG_FORMAT", "json")); v {
	case "json", "text":
		l.Format = v
	default:
		r.fail("APP_LOG_FORMAT must be json or text: %q", v)
	}
	return l
}

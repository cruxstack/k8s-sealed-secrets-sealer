// Package config reads and validates the configuration of the control plane
// and the agent. It is the only package that reads the environment, except
// that the AWS SDK reads its own standard variables (credentials, region).
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
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
	// RegistryFile is the agent registry (see internal/registry).
	RegistryFile string
	// AgentSessionKey signs agent session tokens.
	AgentSessionKey []byte
	// AdminToken enables the admin API when set.
	AdminToken string

	DynamoDBTable string
	// DynamoDBEndpoint overrides the DynamoDB endpoint, for local emulators.
	DynamoDBEndpoint string
	// DynamoDBCreateTable creates the table at startup. Local emulators only.
	DynamoDBCreateTable bool

	// AWSSTSHosts, when set, replaces the default STS hosts agents' signed
	// login requests may target.
	AWSSTSHosts []string
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
}

// HasCapability reports whether the agent has capability c.
func (a *Agent) HasCapability(c string) bool { return slices.Contains(a.Capabilities, c) }

// LoadControlPlane reads the control plane's configuration from the
// environment and reports every invalid setting at once.
func LoadControlPlane() (*ControlPlane, error) {
	return loadControlPlane(os.LookupEnv)
}

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
		RegistryFile:        r.required(r.str("APP_REGISTRY_FILE", ""), "APP_REGISTRY_FILE"),
		AgentSessionKey:     []byte(r.secret("APP_AGENT_SESSION_KEY", MinSessionKeyBytes, true)),
		AdminToken:          r.secret("APP_ADMIN_TOKEN", MinAdminTokenBytes, false),
		DynamoDBTable:       r.required(r.str("APP_DYNAMODB_TABLE", ""), "APP_DYNAMODB_TABLE"),
		DynamoDBEndpoint:    r.url("APP_DYNAMODB_ENDPOINT", true),
		DynamoDBCreateTable: r.boolean("APP_DYNAMODB_CREATE_TABLE", false),
	}
	cfg.AgentAudience = r.str("APP_AGENT_AUDIENCE", cfg.PublicURL)
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
		CheckInInterval:           r.duration("APP_CHECKIN_INTERVAL", 15*time.Second, 5*time.Second, 5*time.Minute),
	}
	cfg.ControllerDeployment = r.dnsLabel("APP_CONTROLLER_DEPLOYMENT", cfg.ControllerName)
	cfg.ControlPlaneURL = r.required(r.url("APP_CONTROL_PLANE_URL", cfg.AllowInsecureControlPlane), "APP_CONTROL_PLANE_URL")
	cfg.IdentityAudience = r.str("APP_IDENTITY_AUDIENCE", cfg.ControlPlaneURL)
	cfg.AWSSTSRegion = r.str("APP_AWS_STS_REGION", "")
	switch cfg.IdentityMode = r.str("APP_IDENTITY_MODE", protocol.MethodK8sOIDC); cfg.IdentityMode {
	case protocol.MethodK8sOIDC, protocol.MethodAWSSTS:
	default:
		r.fail("APP_IDENTITY_MODE must be %s or %s: %q", protocol.MethodK8sOIDC, protocol.MethodAWSSTS, cfg.IdentityMode)
	}
	for _, c := range strings.Split(r.str("APP_CAPABILITIES", protocol.CapabilitySeal), ",") {
		c = strings.TrimSpace(c)
		switch {
		case c == "":
		case !protocol.IsCapability(c):
			r.fail("APP_CAPABILITIES: unknown capability %q", c)
		case !slices.Contains(cfg.Capabilities, c):
			cfg.Capabilities = append(cfg.Capabilities, c)
		}
	}
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

func (r *reader) boolean(key string, fallback bool) bool {
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

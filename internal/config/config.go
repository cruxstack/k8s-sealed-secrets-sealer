// Package config reads and validates the configuration of the control plane
// and the agent. It is the only package that reads the environment.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

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
}

// Agent is the agent's configuration.
type Agent struct {
	HTTPAddr string
	Logging  Logging

	// KubeContext selects a kubeconfig context when the agent runs outside a
	// cluster. Empty means the in-cluster configuration.
	KubeContext string

	// ControllerNamespace and ControllerName locate the sealed-secrets
	// controller's Service.
	ControllerNamespace string
	ControllerName      string

	// InventoryInterval is how often the agent re-reads the controller.
	InventoryInterval time.Duration
}

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
		HTTPAddr: r.str("APP_HTTP_ADDR", ":8080"),
		Logging:  r.logging(),
	}
	return cfg, r.err()
}

func loadAgent(lookup lookupFunc) (*Agent, error) {
	r := &reader{lookup: lookup}
	cfg := &Agent{
		HTTPAddr:            r.str("APP_HTTP_ADDR", ":8081"),
		Logging:             r.logging(),
		KubeContext:         r.str("APP_KUBE_CONTEXT", ""),
		ControllerNamespace: r.dnsLabel("APP_CONTROLLER_NAMESPACE", ""),
		ControllerName:      r.dnsLabel("APP_CONTROLLER_NAME", "sealed-secrets-controller"),
		InventoryInterval:   r.duration("APP_INVENTORY_INTERVAL", time.Minute, 10*time.Second, time.Hour),
	}
	if cfg.ControllerNamespace == "" {
		r.fail("APP_CONTROLLER_NAMESPACE is required")
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

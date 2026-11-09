// Package agent runs beside a sealed-secrets controller. In this version it
// reads the controller's active sealing certificate on an interval and
// reports readiness once it has one; check-in, sealing and key sync build on
// this loop.
package agent

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
)

// refreshTimeout bounds one read of the controller.
const refreshTimeout = 15 * time.Second

// Options configures an Agent.
type Options struct {
	Certs    CertSource
	Interval time.Duration
	Logger   *slog.Logger
	Version  string
}

// Agent tracks the controller's active sealing key.
type Agent struct {
	certs    CertSource
	interval time.Duration
	logger   *slog.Logger
	version  string

	mu     sync.RWMutex
	active *Key
}

// New returns an Agent. It makes no network calls.
func New(opts Options) *Agent {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Agent{
		certs:    opts.Certs,
		interval: opts.Interval,
		logger:   logger,
		version:  opts.Version,
	}
}

// Run reads the controller now and then every interval until ctx ends.
// Failed reads are logged and retried on the next tick.
func (a *Agent) Run(ctx context.Context) error {
	a.refresh(ctx)
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			a.refresh(ctx)
		}
	}
}

// ActiveKey returns the controller's active key, if one has been read.
func (a *Agent) ActiveKey() (Key, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.active == nil {
		return Key{}, false
	}
	return *a.active, true
}

func (a *Agent) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()

	pemBytes, err := a.certs.ActiveCert(ctx)
	if err != nil {
		a.logger.WarnContext(ctx, "failed to read controller certificate",
			"event", "controller.cert_failed", "error", err)
		return
	}
	key, _, err := ParseCert(pemBytes)
	if err != nil {
		a.logger.WarnContext(ctx, "controller returned an unusable certificate",
			"event", "controller.cert_failed", "error", err)
		return
	}

	a.mu.Lock()
	prev := a.active
	a.active = &key
	a.mu.Unlock()

	if prev == nil || prev.Fingerprint != key.Fingerprint {
		a.logger.InfoContext(ctx, "controller sealing key is active",
			"event", "controller.key_active",
			"fingerprint", key.Fingerprint,
			"not_before", key.NotBefore,
			"not_after", key.NotAfter,
			"bits", key.Bits)
	}
	if time.Now().After(key.NotAfter) {
		a.logger.WarnContext(ctx, "controller sealing certificate has expired",
			"event", "controller.cert_expired",
			"fingerprint", key.Fingerprint,
			"not_after", key.NotAfter)
	}
}

// Handler serves the agent's probes: /healthz answers while the process runs
// and /readyz once the controller's certificate has been read.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": a.version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		key, ok := a.ActiveKey()
		if !ok {
			httpserver.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "waiting for controller certificate"})
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "fingerprint": key.Fingerprint})
	})
	return mux
}

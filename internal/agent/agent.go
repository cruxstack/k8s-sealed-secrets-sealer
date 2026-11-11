// Package agent runs beside a sealed-secrets controller. On every interval
// it reads the controller's keys and settings and checks in with the control
// plane, uploading keys the env has no escrowed copy of; alongside, it polls
// for commands and runs them.
package agent

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
)

// cycleTimeout bounds one inventory and check-in.
const cycleTimeout = 30 * time.Second

// keysWarnAt is how many keys make the agent warn that its key set nears the
// most the control plane keeps track of (protocol.MaxKeys).
const keysWarnAt = protocol.MaxKeys * 4 / 5

// Collector reads the controller.
type Collector interface {
	Collect(ctx context.Context) (Report, error)
}

// CheckInClient reports to the control plane.
type CheckInClient interface {
	CheckIn(ctx context.Context, in protocol.CheckIn) (*protocol.CheckInResponse, error)
}

// Escrower uploads keys the control plane has no escrowed copy of.
type Escrower interface {
	Escrow(ctx context.Context, fingerprints []string)
}

// KeyLoader gets the controller to load keys restored into it, and drop
// keys deleted from it; active is the key it seals with.
type KeyLoader interface {
	LoadRestored(ctx context.Context, active string)
	// DeletedLoaded reports whether controller pods may still hold keys
	// the agent deleted, because their restart failed.
	DeletedLoaded() bool
}

// UsageReporter has the latest count of the values the controller's
// SealedSecrets hold by key, nil before the first.
type UsageReporter interface {
	Latest() *protocol.KeyUsage
}

// Options configures an Agent.
type Options struct {
	Inventory    Collector
	ControlPlane CheckInClient
	Interval     time.Duration
	Capabilities []string
	// Commands are the command types the agent runs.
	Commands []string
	// Escrow uploads keys after a check-in asks for them, and Loader
	// restarts the controller while restored keys are not loaded; both are
	// nil without the keys capability.
	Escrow Escrower
	Loader KeyLoader
	// Usage is the agent's count of key references, reported with each
	// check-in; nil without the cleanup capability.
	Usage   UsageReporter
	Logger  *slog.Logger
	Version string
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Agent reports its controller to the control plane on an interval.
type Agent struct {
	inventory    Collector
	controlPlane CheckInClient
	interval     time.Duration
	capabilities []string
	commands     []string
	escrow       Escrower
	loader       KeyLoader
	usage        UsageReporter
	logger       *slog.Logger
	version      string
	now          func() time.Time

	mu          sync.RWMutex
	active      string
	lastCheckIn time.Time
	keyCount    int
}

// New returns an Agent. It makes no network calls.
func New(opts Options) *Agent {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Agent{
		inventory:    opts.Inventory,
		controlPlane: opts.ControlPlane,
		interval:     opts.Interval,
		capabilities: opts.Capabilities,
		commands:     opts.Commands,
		escrow:       opts.Escrow,
		loader:       opts.Loader,
		usage:        opts.Usage,
		logger:       logger,
		version:      opts.Version,
		now:          now,
	}
}

// Run checks in now and then every interval until ctx ends. Failures are
// logged and retried on the next tick.
func (a *Agent) Run(ctx context.Context) error {
	a.cycle(ctx)
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			a.cycle(ctx)
		}
	}
}

func (a *Agent) cycle(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, cycleTimeout)
	defer cancel()

	report, err := a.inventory.Collect(cycleCtx)
	if err != nil {
		a.logger.WarnContext(cycleCtx, "failed to read controller",
			"event", "controller.read_failed", "error", err)
		return
	}
	a.noteActiveKey(cycleCtx, report)
	a.noteKeyCount(cycleCtx, len(report.Keys))
	a.checkIn(cycleCtx, report)

	// restored keys are loaded, and deleted ones dropped, whether or not
	// the control plane answered: decryption must never wait for it. The
	// restart gets time of its own, so a check-in that timed out does not
	// cut it short.
	if a.loader != nil && (len(report.Pending) > 0 || a.loader.DeletedLoaded()) {
		loadCtx, cancel := context.WithTimeout(ctx, cycleTimeout)
		defer cancel()
		a.loader.LoadRestored(loadCtx, report.Controller.ActiveFingerprint)
	}
}

// checkIn reports the controller to the control plane and escrows the keys
// it asks for.
func (a *Agent) checkIn(ctx context.Context, report Report) {
	// an agent with no capabilities still checks in, reporting its
	// controller's active key; empty lists, not null
	capabilities, commands := a.capabilities, a.commands
	if capabilities == nil {
		capabilities = []string{}
	}
	if commands == nil {
		commands = []string{}
	}
	in := protocol.CheckIn{
		Protocol:     protocol.Version,
		AgentVersion: a.version,
		Capabilities: capabilities,
		Commands:     commands,
		Controller:   report.Controller,
		Keys:         report.Keys,
		KeysComplete: report.Complete,
	}
	if a.usage != nil {
		in.KeyUsage = a.usage.Latest()
	}
	resp, err := a.controlPlane.CheckIn(ctx, in)
	if err != nil {
		a.logger.WarnContext(ctx, "failed to check in with the control plane",
			"event", "agent.checkin_failed", "error", err)
		return
	}
	a.mu.Lock()
	first := a.lastCheckIn.IsZero()
	a.lastCheckIn = a.now()
	a.mu.Unlock()
	if first {
		a.logger.InfoContext(ctx, "checked in with the control plane",
			"event", "agent.checked_in", "keys", len(report.Keys), "keys_complete", report.Complete)
	}
	if a.escrow != nil && len(resp.EscrowNeeded) > 0 {
		a.escrow.Escrow(ctx, resp.EscrowNeeded)
	}
}

// noteKeyCount warns when the key set reaches keysWarnAt keys, and again
// whenever the count changes from there: past protocol.MaxKeys, the control
// plane keeps the newest and leaves the oldest out of key sync.
func (a *Agent) noteKeyCount(ctx context.Context, n int) {
	a.mu.Lock()
	changed := a.keyCount != n
	a.keyCount = n
	a.mu.Unlock()
	switch {
	case !changed || n < keysWarnAt:
	case n > protocol.MaxKeys:
		a.logger.ErrorContext(ctx, "controller holds more sealing keys than the control plane keeps; the oldest are left out of key sync",
			"event", "controller.too_many_keys", "keys", n, "limit", protocol.MaxKeys)
	default:
		a.logger.WarnContext(ctx, "controller holds nearly as many sealing keys as the control plane keeps",
			"event", "controller.many_keys", "keys", n, "limit", protocol.MaxKeys)
	}
}

func (a *Agent) noteActiveKey(ctx context.Context, r Report) {
	fp := r.Controller.ActiveFingerprint
	a.mu.Lock()
	changed := a.active != fp
	a.active = fp
	a.mu.Unlock()
	if !changed {
		return
	}
	for _, k := range r.Keys {
		if k.Fingerprint != fp {
			continue
		}
		a.logger.InfoContext(ctx, "controller sealing key is active",
			"event", "controller.key_active",
			"fingerprint", k.Fingerprint, "not_before", k.NotBefore, "not_after", k.NotAfter)
		if a.now().After(k.NotAfter) {
			a.logger.WarnContext(ctx, "controller sealing certificate has expired",
				"event", "controller.cert_expired", "fingerprint", k.Fingerprint, "not_after", k.NotAfter)
		}
	}
}

// ready reports whether the agent checked in recently: within three
// intervals, so one slow or failed check-in does not flip it.
func (a *Agent) ready() (bool, time.Time, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	ok := !a.lastCheckIn.IsZero() && a.now().Sub(a.lastCheckIn) <= 3*a.interval
	return ok, a.lastCheckIn, a.active
}

// Handler serves the agent's probes: /healthz answers while the process runs
// and /readyz while check-ins succeed.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": a.version})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		ok, last, active := a.ready()
		if !ok {
			httpserver.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not checked in recently"})
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{
			"status": "ok", "last_checkin": last.UTC().Format(time.RFC3339), "active_fingerprint": active,
		})
	})
	return mux
}

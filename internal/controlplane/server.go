// Package controlplane serves the control plane's HTTP API. It has no
// Kubernetes client: everything it knows about clusters comes from agents.
package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/envelope"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/repos"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// LoginVerifier checks the identity in an agent's login request.
type LoginVerifier interface {
	VerifyLogin(ctx context.Context, req protocol.SessionRequest) (*registry.Agent, error)
}

// UserGuard admits people to one env's user API (userauth.EnvGuard).
type UserGuard interface {
	// RequireUser rejects requests without a session that grants the env,
	// and puts the user, as the env sees them, in the request context.
	RequireUser(http.HandlerFunc) http.HandlerFunc
	// RequireCSRF rejects state-changing requests without the session's
	// CSRF token.
	RequireCSRF(http.HandlerFunc) http.HandlerFunc
	// RequireAdmin rejects users who do not administer the env.
	RequireAdmin(http.HandlerFunc) http.HandlerFunc
}

// Options configures a Server: one env's control plane. A Host serves one
// or more of them, with sign-in and the web UI.
type Options struct {
	Logger   *slog.Logger
	Version  string
	Env      string
	Registry *registry.Registry
	// Logins verifies login requests, by login method, against Registry.
	Logins map[string]LoginVerifier
	// ReloadRegistry, when set, reads the registry again and returns it
	// with login verifiers built for it, or a nil registry when it has not
	// changed. The server calls it about once a RegistryReloadInterval and
	// serves what it returns from then on; when it fails, the server keeps
	// what it has.
	ReloadRegistry func(ctx context.Context) (*registry.Registry, map[string]LoginVerifier, error)
	Sessions       *agentauth.Sessions
	Store          store.Store
	// AdminToken enables the admin API. Empty disables it.
	AdminToken string
	// AdminTokenKeyChanges lets the admin token revoke, reinstate and
	// delete keys. Without it the token only reads the fleet; signed-in
	// admins change keys either way.
	AdminTokenKeyChanges bool
	// Users admits people to the env's user API; nil disables it. Signing
	// in is the Host's.
	Users UserGuard
	// Repos gives signed-in users access to repositories; nil disables the
	// repository API.
	Repos *repos.Service
	// Transit encrypts values for seal commands under TransitKeyID. It can
	// only generate data keys: the control plane never decrypts a value.
	// Sealing needs both Repos and Transit.
	Transit      envelope.DataKeyGenerator
	TransitKeyID string
	// HSTS sets Strict-Transport-Security, for deployments served over https.
	HSTS bool
	// KeyRenewPeriod is the period renewal.enable.v1 sets when no cluster
	// renews its key. Zero means DefaultKeyRenewPeriod.
	KeyRenewPeriod time.Duration
	// PollInterval is how often a held commands poll checks for new
	// commands. Zero means DefaultPollInterval.
	PollInterval time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Defaults for Options.
const (
	DefaultKeyRenewPeriod = 720 * time.Hour
	DefaultPollInterval   = 500 * time.Millisecond
)

// RegistryReloadInterval is how often a server with Options.ReloadRegistry
// reads its registry again, and registryReloadTimeout bounds each read.
const (
	RegistryReloadInterval = time.Minute
	registryReloadTimeout  = 5 * time.Second
)

// Server is the control plane's HTTP handler. The same handler runs behind
// the HTTP server and the Lambda adapter.
type Server struct {
	logger     *slog.Logger
	version    string
	env        string
	sessions   *agentauth.Sessions
	store      store.Store
	adminToken string
	users      UserGuard
	repos      *repos.Service
	transit    envelope.DataKeyGenerator
	transitKey string
	hsts       bool
	now        func() time.Time

	// adminTokenKeyChanges lets the admin token change keys
	adminTokenKeyChanges bool

	keyRenewPeriod time.Duration
	pollInterval   time.Duration

	// agents is the registry in force and the login verifiers built for it,
	// replaced together when the registry is read again
	agents         atomic.Pointer[agentAccess]
	reloadRegistry func(context.Context) (*registry.Registry, map[string]LoginVerifier, error)
	// reloadMu is held while the registry is read again, by the goroutine
	// reading it; reloading counts those goroutines, for tests
	reloadMu  sync.Mutex
	reloading sync.WaitGroup
	// nextReload is when the registry is next read, in Unix nanoseconds
	nextReload atomic.Int64

	// knownKeys caches fingerprints already recorded, so repeated check-ins
	// do not repeat conditional writes; knownEscrow caches who escrowed a
	// copy of each key. Losing either only costs reads and writes.
	knownMu     sync.Mutex
	knownKeys   map[string]bool
	knownEscrow map[string]knownCopies

	// histories caches each agent's restore failures for the escrow
	// downloads of one restore
	historyMu sync.Mutex
	histories map[string]restoreHistory
	// localCounts counts rate-limited requests while the store cannot
	localCounts localCounts
}

// New returns a Server. It makes no network calls.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	keyRenewPeriod := opts.KeyRenewPeriod
	if keyRenewPeriod <= 0 {
		keyRenewPeriod = DefaultKeyRenewPeriod
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}
	s := &Server{
		logger:     logger,
		version:    opts.Version,
		env:        opts.Env,
		sessions:   opts.Sessions,
		store:      opts.Store,
		adminToken: opts.AdminToken,
		users:      opts.Users,
		repos:      opts.Repos,
		transit:    opts.Transit,
		transitKey: opts.TransitKeyID,
		hsts:       opts.HSTS,
		now:        now,

		adminTokenKeyChanges: opts.AdminTokenKeyChanges,

		keyRenewPeriod: keyRenewPeriod,
		pollInterval:   pollInterval,
		reloadRegistry: opts.ReloadRegistry,
		knownKeys:      map[string]bool{},
		knownEscrow:    map[string]knownCopies{},
		histories:      map[string]restoreHistory{},
	}
	s.agents.Store(&agentAccess{reg: opts.Registry, logins: opts.Logins})
	s.nextReload.Store(now().Add(RegistryReloadInterval).UnixNano())
	return s
}

// agentAccess is a registry and the login verifiers built for it.
type agentAccess struct {
	reg    *registry.Registry
	logins map[string]LoginVerifier
}

// currentRegistry returns the registry in force. A handler reads it once
// and uses that throughout.
func (s *Server) currentRegistry() *registry.Registry { return s.agents.Load().reg }

// readingRegistry starts reading the registry again, at most once a
// RegistryReloadInterval, as requests come in. It runs on requests rather
// than a timer because a Lambda instance is frozen between them: however
// long one slept, the first request after a minute starts the read, and a
// removed agent is refused once it is done. The read runs beside the
// requests, never in their time, so it cannot push a poll or a pull request
// past its time limit; they use the registry in force until the read is
// done. On Lambda, a read still running when its request ends is frozen with
// the instance and goes on with its next request.
func (s *Server) readingRegistry(next http.Handler) http.Handler {
	if s.reloadRegistry == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.now().UnixNano() >= s.nextReload.Load() && s.reloadMu.TryLock() {
			s.reloading.Add(1)
			ctx := context.WithoutCancel(r.Context())
			go func() {
				defer s.reloading.Done()
				defer s.reloadMu.Unlock()
				s.reloadRegistryNow(ctx)
			}()
		}
		next.ServeHTTP(w, r)
	})
}

// reloadRegistryNow reads the registry again unless another request just
// started it. It must hold reloadMu.
func (s *Server) reloadRegistryNow(ctx context.Context) {
	started := s.now()
	if started.UnixNano() < s.nextReload.Load() {
		return
	}
	// a failed read waits as long, so a broken source is not read on every
	// request
	s.nextReload.Store(started.Add(RegistryReloadInterval).UnixNano())
	ctx, cancel := context.WithTimeout(ctx, registryReloadTimeout)
	defer cancel()
	reg, logins, err := s.reloadRegistry(ctx)
	switch {
	case err != nil && s.now().Sub(started) > 2*registryReloadTimeout:
		// far longer than a read may take: the instance was frozen in the
		// middle of it, and its time ran out meanwhile. The next request
		// reads it again.
		s.nextReload.Store(started.UnixNano())
		s.logger.InfoContext(ctx, "the agent registry's read was interrupted; reading it again",
			"env", s.env, "error", err)
	case err != nil:
		s.logger.ErrorContext(ctx, "failed to read the agent registry again; keeping the one in force",
			"event", "registry.reload_failed", "env", s.env, "error", err)
	case reg != nil:
		s.agents.Store(&agentAccess{reg: reg, logins: logins})
		s.logger.InfoContext(ctx, "agent registry changed",
			"event", "registry.reloaded", "env", s.env, "agents", len(reg.Agents))
	}
}

// Handler returns the control plane's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)

	mux.HandleFunc("POST /agent/v1/session", s.agentSession)
	mux.HandleFunc("POST /agent/v1/checkin", s.requireAgent(s.agentCheckIn))
	mux.HandleFunc("GET /agent/v1/commands", s.requireAgent(s.agentCommands))
	mux.HandleFunc("POST /agent/v1/commands/{id}/result", s.requireAgent(s.agentCommandResult))
	mux.HandleFunc("PUT /agent/v1/escrow/{fingerprint}", s.requireAgent(s.agentPutEscrow))
	mux.HandleFunc("GET /agent/v1/escrow/{fingerprint}", s.requireAgent(s.agentGetEscrow))

	const revoke, reinstate, del = "/keys/{fingerprint}/revoke", "/keys/{fingerprint}/reinstate", "/keys/{fingerprint}/delete"
	if s.adminToken != "" {
		mux.HandleFunc("GET /api/v1/admin/fleet", s.requireAdmin(s.fleet))
		// the token is often shared, and given to monitoring: changing keys
		// with it is allowed per env
		keyChange := func(h http.HandlerFunc) http.HandlerFunc {
			if !s.adminTokenKeyChanges {
				return s.requireAdmin(adminTokenKeyChangesOff)
			}
			return s.requireAdmin(h)
		}
		mux.HandleFunc("POST /api/v1/admin"+revoke, keyChange(s.setKeyStatus(store.KeyRevoked)))
		mux.HandleFunc("POST /api/v1/admin"+reinstate, keyChange(s.setKeyStatus(store.KeyActive)))
		mux.HandleFunc("POST /api/v1/admin"+del, keyChange(s.deleteKey))
	}

	if u := s.users; u != nil {
		// the fleet is for admins; everyone sees whether sealing works
		mux.HandleFunc("GET /api/v1/fleet", u.RequireUser(u.RequireAdmin(s.fleet)))
		admin := func(h http.HandlerFunc) http.HandlerFunc { return u.RequireUser(u.RequireCSRF(u.RequireAdmin(h))) }
		mux.HandleFunc("POST /api/v1"+revoke, admin(s.setKeyStatus(store.KeyRevoked)))
		mux.HandleFunc("POST /api/v1"+reinstate, admin(s.setKeyStatus(store.KeyActive)))
		mux.HandleFunc("POST /api/v1"+del, admin(s.deleteKey))
		mux.HandleFunc("GET /api/v1/status", u.RequireUser(s.status))
		// calls that cost GitHub requests, KMS or agent work are rate
		// limited per user, after sign-in and CSRF checks
		if s.repos != nil {
			mux.HandleFunc("GET /api/v1/repos", u.RequireUser(s.limit(s.listRepos, limitRepos)))
			mux.HandleFunc("GET /api/v1/repos/{owner}/{repo}/files", u.RequireUser(s.limit(s.listFiles, limitFiles)))
		}
		if s.repos != nil && s.transit != nil {
			// state-changing routes need the CSRF token
			write := func(h http.HandlerFunc) http.HandlerFunc { return u.RequireUser(u.RequireCSRF(h)) }
			const session = "/api/v1/repos/{owner}/{repo}/session"
			mux.HandleFunc("GET /api/v1/sessions", u.RequireUser(s.listSessions))
			mux.HandleFunc("GET "+session, u.RequireUser(s.getSession))
			mux.HandleFunc("POST "+session, write(s.limit(s.createSession, limitSessions)))
			mux.HandleFunc("DELETE "+session+"/{id}", write(s.deleteSession))
			mux.HandleFunc("POST "+session+"/{id}/seals", write(s.limit(s.requestSeal, limitSessionSeals, limitSeals)))
			mux.HandleFunc("GET "+session+"/{id}/seals/{seal}", u.RequireUser(s.getSeal))
			mux.HandleFunc("DELETE "+session+"/{id}/changes/{change}", write(s.deleteChange))
			mux.HandleFunc("POST "+session+"/{id}/pull-request", write(s.limit(s.createPullRequest, limitPulls)))
		}
	}

	notFound := func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not found") }
	mux.HandleFunc("/api/", notFound)
	mux.HandleFunc("/agent/", notFound)
	mux.HandleFunc("/", notFound)
	return httpserver.SecurityHeaders(s.hsts)(s.readingRegistry(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	httpserver.WriteJSON(w, status, protocol.Error{Error: msg})
}

// decodeJSON reads a user API body: JSON of at most limit bytes with no
// unknown fields. On failure it writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	return decodeBody(w, r, limit, v, true)
}

// decodeAgentJSON reads an agent API body: JSON of at most limit bytes. It
// ignores fields it does not know, so an agent of a newer version can send
// more than this control plane reads (docs/design.md, section 5).
func decodeAgentJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	return decodeBody(w, r, limit, v, false)
}

func decodeBody(w http.ResponseWriter, r *http.Request, limit int64, v any, strict bool) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// bearer returns the token from an "Authorization: Bearer" header.
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		return strings.TrimSpace(v[7:])
	}
	return ""
}

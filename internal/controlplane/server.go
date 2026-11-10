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
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// LoginVerifier checks the identity in an agent's login request.
type LoginVerifier interface {
	VerifyLogin(ctx context.Context, req protocol.SessionRequest) (*registry.Agent, error)
}

// Options configures a Server.
type Options struct {
	Logger   *slog.Logger
	Version  string
	Env      string
	Registry *registry.Registry
	// Logins verifies login requests, by login method.
	Logins   map[string]LoginVerifier
	Sessions *agentauth.Sessions
	Store    store.Store
	// AdminToken enables the admin API. Empty disables it.
	AdminToken string
	// Users signs people in and enables the user API. Nil disables both.
	Users *userauth.Handler
	// WebUI serves the web UI at /. Nil serves nothing there.
	WebUI http.Handler
	// HSTS sets Strict-Transport-Security, for deployments served over https.
	HSTS bool
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Server is the control plane's HTTP handler. The same handler runs behind
// the HTTP server and the Lambda adapter.
type Server struct {
	logger     *slog.Logger
	version    string
	env        string
	reg        *registry.Registry
	logins     map[string]LoginVerifier
	sessions   *agentauth.Sessions
	store      store.Store
	adminToken string
	users      *userauth.Handler
	webUI      http.Handler
	hsts       bool
	now        func() time.Time

	// knownKeys caches fingerprints already recorded, so repeated check-ins
	// do not repeat conditional writes. Losing it only costs writes.
	knownMu   sync.Mutex
	knownKeys map[string]bool
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
	return &Server{
		logger:     logger,
		version:    opts.Version,
		env:        opts.Env,
		reg:        opts.Registry,
		logins:     opts.Logins,
		sessions:   opts.Sessions,
		store:      opts.Store,
		adminToken: opts.AdminToken,
		users:      opts.Users,
		webUI:      opts.WebUI,
		hsts:       opts.HSTS,
		now:        now,
		knownKeys:  map[string]bool{},
	}
}

// Handler returns the control plane's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)

	mux.HandleFunc("POST /agent/v1/session", s.agentSession)
	mux.HandleFunc("POST /agent/v1/checkin", s.requireAgent(s.agentCheckIn))

	if s.adminToken != "" {
		mux.HandleFunc("GET /api/v1/admin/fleet", s.requireAdmin(s.fleet))
	}

	if u := s.users; u != nil {
		mux.HandleFunc("GET /api/v1/auth/login", u.Login)
		mux.HandleFunc("GET /api/v1/auth/callback", u.Callback)
		mux.HandleFunc("GET /api/v1/auth/me", u.Me)
		mux.HandleFunc("POST /api/v1/auth/logout", u.RequireUser(u.RequireCSRF(u.Logout)))
		mux.HandleFunc("GET /api/v1/fleet", u.RequireUser(s.fleet))
	}

	notFound := func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not found") }
	mux.HandleFunc("/api/", notFound)
	mux.HandleFunc("/agent/", notFound)
	if s.webUI != nil {
		mux.Handle("/", s.webUI)
	} else {
		mux.HandleFunc("/", notFound)
	}
	return httpserver.SecurityHeaders(s.hsts)(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	httpserver.WriteJSON(w, status, protocol.Error{Error: msg})
}

// decodeJSON reads a JSON body of at most limit bytes with no unknown fields.
// On failure it writes the error response and returns false.
func decodeJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
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

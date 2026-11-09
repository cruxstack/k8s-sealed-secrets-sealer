// Package controlplane serves the control plane's HTTP API. It has no
// Kubernetes client: everything it knows about clusters comes from agents.
package controlplane

import (
	"log/slog"
	"net/http"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
)

// Options configures a Server.
type Options struct {
	Logger  *slog.Logger
	Version string
}

// Server is the control plane's HTTP handler. The same handler runs behind
// the HTTP server and the Lambda adapter.
type Server struct {
	logger  *slog.Logger
	version string
}

// New returns a Server. It makes no network calls.
func New(opts Options) *Server {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{logger: logger, version: opts.Version}
}

// Handler returns the control plane's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		httpserver.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.version})
}

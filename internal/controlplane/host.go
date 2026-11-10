package controlplane

import (
	"net/http"
	"strings"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/httpserver"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// HostOptions configures a Host.
type HostOptions struct {
	Version string
	// Users signs people in, once for every env.
	Users *userauth.Handler
	// Envs are the envs served, in the order people see them. Each is a
	// Server built without a web UI.
	Envs []*Server
	// WebUI serves the web UI at /. Nil serves nothing there.
	WebUI http.Handler
	// HSTS sets Strict-Transport-Security, for deployments served over https.
	HSTS bool
}

// NewHost serves one or more envs on one URL:
//
//   - sign-in, for every env at once, under /api/v1/auth/;
//   - each env's user API under /api/v1/envs/{env}/, as that env's Server
//     serves it under /api/v1/; with a single env, also under /api/v1/;
//   - the agent API under /agent/, sent to the env the agent names in
//     protocol.EnvHeader (with a single env, the header may be left out);
//   - the web UI, which is the same for every env, everywhere else.
func NewHost(opts HostOptions) http.Handler {
	envs := map[string]http.Handler{}
	for _, s := range opts.Envs {
		envs[s.env] = s.Handler()
	}
	var only http.Handler
	if len(opts.Envs) == 1 {
		only = envs[opts.Envs[0].env]
	}
	notFound := func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "not found") }
	health := func(w http.ResponseWriter, _ *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": opts.Version})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /readyz", health)

	if u := opts.Users; u != nil {
		mux.HandleFunc("GET /api/v1/auth/login", u.Login)
		mux.HandleFunc("GET /api/v1/auth/callback", u.Callback)
		mux.HandleFunc("GET /api/v1/auth/me", u.Me)
		mux.HandleFunc("POST /api/v1/auth/logout", u.RequireUser(u.RequireCSRF(u.Logout)))
	}
	mux.HandleFunc("/api/v1/envs/{env}/", func(w http.ResponseWriter, r *http.Request) {
		env := r.PathValue("env")
		h, ok := envs[env]
		if !ok {
			writeError(w, http.StatusNotFound, "this control plane does not serve the "+env+" env")
			return
		}
		h.ServeHTTP(w, withPrefixRemoved(r, "/envs/"+env))
	})
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if only == nil {
			notFound(w, r)
			return
		}
		only.ServeHTTP(w, r)
	})
	mux.HandleFunc("/agent/", func(w http.ResponseWriter, r *http.Request) {
		env := r.Header.Get(protocol.EnvHeader)
		h, ok := envs[env]
		switch {
		case env == "" && only != nil:
			h = only
		case env == "":
			writeError(w, http.StatusBadRequest, "this control plane serves several envs: name the agent's env in "+protocol.EnvHeader)
			return
		case !ok:
			writeError(w, http.StatusNotFound, "this control plane does not serve the "+env+" env")
			return
		}
		h.ServeHTTP(w, r)
	})
	if opts.WebUI != nil {
		mux.Handle("/", opts.WebUI)
	} else {
		mux.HandleFunc("/", notFound)
	}
	return httpserver.SecurityHeaders(opts.HSTS)(mux)
}

// withPrefixRemoved returns r with prefix taken out of its path after
// /api/v1, so /api/v1/envs/dev/repos reaches an env's server as
// /api/v1/repos.
func withPrefixRemoved(r *http.Request, prefix string) *http.Request {
	const api = "/api/v1"
	r2 := r.Clone(r.Context())
	r2.URL.Path = api + strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, api), prefix)
	if r.URL.RawPath != "" {
		r2.URL.RawPath = api + strings.TrimPrefix(strings.TrimPrefix(r.URL.RawPath, api), prefix)
	}
	return r2
}

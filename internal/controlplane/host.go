package controlplane

import (
	"net/http"
	"path"
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
	// Setup, while the GitHub App is not set up, serves the setup API
	// under /api/v1/setup. Every page is then the setup page, whose form
	// may post to SetupFormAction (GitHub), and sign-in is not served:
	// Users is nil until the App exists.
	Setup           http.Handler
	SetupFormAction string
}

// NewHost serves one or more envs on one URL:
//
//   - sign-in, for every env at once, under /api/v1/auth/;
//   - each env's user API under /api/v1/envs/{env}/, as that env's Server
//     serves it under /api/v1/; with a single env, also under /api/v1/;
//   - the agent API under /agent/, sent to the env the agent names in
//     protocol.EnvHeader (with a single env, the header may be left out);
//   - the web UI, which is the same for every env, everywhere else;
//   - while the GitHub App is not set up, the setup API under
//     /api/v1/setup, and the setup page in place of every other page.
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
	if opts.Setup != nil {
		mux.Handle("/api/v1/setup", opts.Setup)
		mux.Handle("/api/v1/setup/", opts.Setup)
		mux.HandleFunc("/api/v1/auth/", func(w http.ResponseWriter, _ *http.Request) {
			writeError(w, http.StatusServiceUnavailable, "the GitHub App is not set up yet: open /setup")
		})
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
	switch {
	case opts.WebUI != nil && opts.Setup != nil:
		mux.Handle("/", setupPages(opts.WebUI))
	case opts.WebUI != nil:
		mux.Handle("/", opts.WebUI)
	default:
		mux.HandleFunc("/", notFound)
	}
	if opts.Setup != nil && opts.SetupFormAction != "" {
		return httpserver.SecurityHeaders(opts.HSTS, opts.SetupFormAction)(mux)
	}
	return httpserver.SecurityHeaders(opts.HSTS)(mux)
}

// setupPages sends every page but the setup page to it, and serves the
// UI's files: nothing else works until the GitHub App is set up.
func setupPages(ui http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		page := !strings.HasPrefix(p, "/assets/") && path.Ext(p) == ""
		if page && p != "/setup" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		ui.ServeHTTP(w, r)
	})
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

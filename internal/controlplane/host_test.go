package controlplane

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

// twoEnvs is a host serving dev and prod, each with its own agent, store
// and agent session key, and one sign-in for both.
type twoEnvs struct {
	h             http.Handler
	users         *userauth.Sessions
	agentSessions map[string]*agentauth.Sessions
}

func newTwoEnvs(t *testing.T) *twoEnvs {
	t.Helper()
	users, err := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "https://sealer.example.com", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: users, PublicURL: "https://sealer.example.com", Org: "example-org",
		Envs:   []userauth.EnvPolicy{{Name: "dev"}, {Name: "prod"}},
		Logger: slog.New(slog.DiscardHandler),
	})
	te := &twoEnvs{users: users, agentSessions: map[string]*agentauth.Sessions{}}
	var envs []*Server
	for _, env := range []string{"dev", "prod"} {
		reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: `+env+`-use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:`+env+`:agent"}}}
`), "")
		if err != nil {
			t.Fatal(err)
		}
		// each env signs agent sessions with its own key
		s, err := agentauth.NewSessions([]byte(strings.Repeat(env[:1], 32)), "https://sealer.example.com", env, nil)
		if err != nil {
			t.Fatal(err)
		}
		te.agentSessions[env] = s
		envs = append(envs, New(Options{
			Env: env, Registry: reg, Sessions: s, Store: store.NewMemory(),
			Users: auth.Env(env), Logger: slog.New(slog.DiscardHandler),
		}))
	}
	te.h = NewHost(HostOptions{
		Users: auth, Envs: envs, HSTS: true,
		WebUI: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>ui</html>")) }),
	})
	return te
}

func (te *twoEnvs) get(path, session string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-sealer_session", Value: session})
	}
	rec := httptest.NewRecorder()
	te.h.ServeHTTP(rec, req)
	return rec
}

func TestHost_UserAPIPerEnv(t *testing.T) {
	te := newTwoEnvs(t)
	both, _, _ := te.users.Issue(userauth.User{ID: 1001, Login: "alice"}, userauth.Grants{"dev": true, "prod": false})
	devOnly, _, _ := te.users.Issue(userauth.User{ID: 1004, Login: "dave"}, userauth.Grants{"dev": false})

	// each env answers under its own path, for itself
	for _, env := range []string{"dev", "prod"} {
		rec := te.get("/api/v1/envs/"+env+"/status", both)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"env":"`+env+`"`) {
			t.Fatalf("%s status = %d %s", env, rec.Code, rec.Body)
		}
	}
	// a session works only in the envs it grants, and admins are per env
	if rec := te.get("/api/v1/envs/prod/status", devOnly); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "may not use the prod env") {
		t.Fatalf("prod for a dev-only user = %d %s", rec.Code, rec.Body)
	}
	if rec := te.get("/api/v1/envs/dev/fleet", both); rec.Code != http.StatusOK {
		t.Fatalf("dev fleet for its admin = %d", rec.Code)
	}
	if rec := te.get("/api/v1/envs/prod/fleet", both); rec.Code != http.StatusForbidden {
		t.Fatalf("prod fleet for a user who does not administer prod = %d", rec.Code)
	}
	// with several envs, the API names one
	if rec := te.get("/api/v1/status", both); rec.Code != http.StatusNotFound {
		t.Fatalf("status without an env = %d", rec.Code)
	}
	if rec := te.get("/api/v1/envs/stage/status", both); rec.Code != http.StatusNotFound ||
		!strings.Contains(rec.Body.String(), "does not serve the stage env") {
		t.Fatalf("an env not served = %d %s", rec.Code, rec.Body)
	}
	// one UI for every env, with the security headers
	rec := te.get("/prod/secrets/example-org/apps", "")
	if rec.Body.String() != "<html>ui</html>" || !strings.Contains(rec.Header().Get("Strict-Transport-Security"), "max-age=") {
		t.Fatalf("ui = %d %s %v", rec.Code, rec.Body, rec.Header())
	}
	if rec := te.get("/healthz", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
}

func TestHost_AgentsByEnv(t *testing.T) {
	te := newTwoEnvs(t)
	checkIn := func(env, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/agent/v1/checkin", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		if env != "" {
			req.Header.Set(protocol.EnvHeader, env)
		}
		rec := httptest.NewRecorder()
		te.h.ServeHTTP(rec, req)
		return rec
	}
	devToken, _, _ := te.agentSessions["dev"].Issue("dev-use1-blue")

	// past authentication, an empty check-in is invalid: the token was good
	if rec := checkIn("dev", devToken); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid check-in") {
		t.Fatalf("dev agent in dev = %d %s", rec.Code, rec.Body)
	}
	// prod does not take dev's sessions
	if rec := checkIn("prod", devToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("dev agent in prod = %d %s", rec.Code, rec.Body)
	}
	if rec := checkIn("", devToken); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), protocol.EnvHeader) {
		t.Fatalf("agent without an env = %d %s", rec.Code, rec.Body)
	}
	if rec := checkIn("stage", devToken); rec.Code != http.StatusNotFound {
		t.Fatalf("agent of an env not served = %d %s", rec.Code, rec.Body)
	}
}

func TestHost_OneEnvNeedsNoEnvInPaths(t *testing.T) {
	users, _ := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "https://sealer.example.com", time.Hour, nil)
	auth := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: users, PublicURL: "https://sealer.example.com", Org: "example-org",
		Envs: []userauth.EnvPolicy{{Name: "dev"}}, Logger: slog.New(slog.DiscardHandler),
	})
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: dev-use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	agents, _ := agentauth.NewSessions([]byte(strings.Repeat("d", 32)), "https://sealer.example.com", "dev", nil)
	h := NewHost(HostOptions{Users: auth, Envs: []*Server{New(Options{
		Env: "dev", Registry: reg, Sessions: agents, Store: store.NewMemory(),
		Users: auth.Env("dev"), Logger: slog.New(slog.DiscardHandler),
	})}})
	session, _, _ := users.Issue(userauth.User{ID: 1001, Login: "alice"}, userauth.Grants{"dev": false})
	for _, path := range []string{"/api/v1/status", "/api/v1/envs/dev/status"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(&http.Cookie{Name: "__Host-sealer_session", Value: session})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s = %d %s", path, rec.Code, rec.Body)
		}
	}
	// agents that do not name their env reach the only one; others are
	// refused
	for env, want := range map[string]int{"": http.StatusUnauthorized, "dev": http.StatusUnauthorized, "prod": http.StatusNotFound} {
		req := httptest.NewRequest(http.MethodPost, "/agent/v1/checkin", strings.NewReader("{}"))
		if env != "" {
			req.Header.Set(protocol.EnvHeader, env)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("agent of env %q = %d, want %d", env, rec.Code, want)
		}
	}
}

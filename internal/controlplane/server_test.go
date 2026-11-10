package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/keys"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/testutil/testcerts"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/userauth"
)

const adminToken = "admin-0123456789abcdef0123456789abcdef"

// fakeVerifier maps login tokens to registered agent IDs.
type fakeVerifier struct {
	reg    *registry.Registry
	tokens map[string]string
}

func (f fakeVerifier) VerifyLogin(_ context.Context, req protocol.SessionRequest) (*registry.Agent, error) {
	token := req.Token
	if req.AWS != nil {
		token = req.AWS.Body
	}
	if id, ok := f.tokens[token]; ok {
		a, _ := f.reg.Agent(id)
		return a, nil
	}
	return nil, agentauth.ErrUnauthorized
}

type harness struct {
	t     *testing.T
	h     http.Handler
	store *store.Memory
	logs  *bytes.Buffer
}

func newHarness(t *testing.T, admin string) *harness {
	t.Helper()
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal, keys], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
  - {id: use2-blue, cluster: blue, region: use2, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:b:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	mem := store.NewMemory()
	srv := New(Options{
		Logger:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Version:  "test",
		Env:      "dev",
		Registry: reg,
		Logins: map[string]LoginVerifier{
			protocol.MethodK8sOIDC: fakeVerifier{reg: reg, tokens: map[string]string{"blue-sa-token": "use1-blue"}},
			protocol.MethodAWSSTS:  fakeVerifier{reg: reg, tokens: map[string]string{"signed-by-use2": "use2-blue"}},
		},
		Sessions:   sessions,
		Store:      mem,
		AdminToken: admin,
	})
	return &harness{t: t, h: srv.Handler(), store: mem, logs: logs}
}

func (h *harness) do(method, path, auth string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if s, ok := body.(string); ok {
			buf.WriteString(s)
		} else if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h *harness) login() string {
	h.t.Helper()
	rec := h.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: "blue-sa-token"})
	if rec.Code != http.StatusOK {
		h.t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	var resp protocol.SessionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		h.t.Fatal(err)
	}
	if resp.AgentID != "use1-blue" || resp.Env != "dev" {
		h.t.Fatalf("session = %+v", resp)
	}
	return resp.Token
}

func protoKey(t *testing.T, notBefore time.Time) protocol.Key {
	t.Helper()
	pem := testcerts.SelfSigned(t, testcerts.RSA(t, 2048), notBefore)
	k, _, err := keys.ParseCert(pem)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.Key{Fingerprint: k.Fingerprint, NotBefore: k.NotBefore, NotAfter: k.NotAfter, Certificate: string(pem)}
}

func checkIn(ks ...protocol.Key) protocol.CheckIn {
	return protocol.CheckIn{
		Protocol:     protocol.Version,
		AgentVersion: "v0.1.0",
		Capabilities: []string{protocol.CapabilitySeal, protocol.CapabilityKeys},
		Controller: protocol.Controller{
			Namespace: "sealed-secrets", Name: "sealed-secrets-controller",
			KeyRenewPeriod: "720h0m0s", KeyOrderPriority: "CertNotBefore",
			ActiveFingerprint: ks[len(ks)-1].Fingerprint,
		},
		Keys:         ks,
		KeysComplete: true,
	}
}

func TestHealth(t *testing.T) {
	h := newHarness(t, "")
	for _, p := range []string{"/healthz", "/readyz"} {
		if rec := h.do(http.MethodGet, p, "", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"version":"test"`) {
			t.Errorf("%s = %d %s", p, rec.Code, rec.Body)
		}
	}
	if rec := h.do(http.MethodGet, "/nope", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d", rec.Code)
	}
}

func TestSession_Rejects(t *testing.T) {
	h := newHarness(t, "")
	cases := map[string]struct {
		body any
		want int
	}{
		"unknown method": {protocol.SessionRequest{Method: "password", Token: "blue-sa-token"}, http.StatusBadRequest},
		"bad token":      {protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: "stolen"}, http.StatusUnauthorized},
		"unknown field":  {`{"method":"k8s-oidc","token":"blue-sa-token","admin":true}`, http.StatusBadRequest},
		"too large":      {`{"method":"k8s-oidc","token":"` + strings.Repeat("a", maxSessionBody) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if rec := h.do(http.MethodPost, "/agent/v1/session", "", tc.body); rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body)
			}
		})
	}
	if !strings.Contains(h.logs.String(), "event=agent.login_rejected") {
		t.Error("rejected login was not logged")
	}
}

type throttledVerifier struct{}

func (throttledVerifier) VerifyLogin(context.Context, protocol.SessionRequest) (*registry.Agent, error) {
	return nil, fmt.Errorf("%w: sts call limit reached", agentauth.ErrTooManyLogins)
}

func TestSession_Throttled(t *testing.T) {
	sessions, _ := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	logs := &bytes.Buffer{}
	srv := New(Options{
		Logger:   slog.New(slog.NewTextHandler(logs, nil)),
		Env:      "dev",
		Registry: &registry.Registry{},
		Logins:   map[string]LoginVerifier{protocol.MethodAWSSTS: throttledVerifier{}},
		Sessions: sessions,
		Store:    store.NewMemory(),
	})
	h := &harness{t: t, h: srv.Handler(), logs: logs}
	rec := h.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodAWSSTS, AWS: &protocol.SignedRequest{}})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("throttled login = %d %v", rec.Code, rec.Header())
	}
	if !strings.Contains(logs.String(), "event=agent.login_throttled") {
		t.Fatalf("logs:\n%s", logs)
	}
}

func TestCheckIn_StoresStateAndDiscoversKeysOnce(t *testing.T) {
	h := newHarness(t, "")
	session := h.login()
	old := protoKey(t, time.Now().Add(-48*time.Hour))
	active := protoKey(t, time.Now().Add(-time.Hour))

	for range 2 {
		rec := h.do(http.MethodPost, "/agent/v1/checkin", session, checkIn(old, active))
		if rec.Code != http.StatusOK {
			t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
		}
	}
	states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"})
	s := states["use1-blue"]
	if len(s.Keys) != 2 || s.Controller.ActiveFingerprint != active.Fingerprint || !s.KeysComplete {
		t.Fatalf("state = %+v", s)
	}
	if rec, ok := h.store.Key(active.Fingerprint); !ok || rec.FirstSeenAgent != "use1-blue" || rec.Certificate != active.Certificate {
		t.Fatalf("key record = %+v %v", rec, ok)
	}
	if n := strings.Count(h.logs.String(), "event=key.discovered"); n != 2 {
		t.Errorf("key.discovered logged %d times, want 2 (once per key)", n)
	}
}

func TestCheckIn_LimitsCapabilitiesToRegistry(t *testing.T) {
	h := newHarness(t, "")
	session := h.login()
	in := checkIn(protoKey(t, time.Now().Add(-time.Hour)))
	in.Capabilities = []string{protocol.CapabilitySeal, protocol.CapabilityRenewal}
	if rec := h.do(http.MethodPost, "/agent/v1/checkin", session, in); rec.Code != http.StatusOK {
		t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
	}
	states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"})
	if got := states["use1-blue"].Capabilities; len(got) != 1 || got[0] != protocol.CapabilitySeal {
		t.Errorf("capabilities = %v, want [seal]", got)
	}
	if !strings.Contains(h.logs.String(), "event=agent.capability_ignored") {
		t.Error("ignored capability was not logged")
	}
}

func TestCheckIn_Rejects(t *testing.T) {
	h := newHarness(t, "")
	session := h.login()
	good := protoKey(t, time.Now().Add(-time.Hour))
	other := protoKey(t, time.Now().Add(-time.Hour))

	mutate := func(f func(*protocol.CheckIn)) protocol.CheckIn {
		in := checkIn(good)
		f(&in)
		return in
	}
	cases := map[string]struct {
		auth string
		body any
		want int
		msg  string
	}{
		"no session":           {"", checkIn(good), http.StatusUnauthorized, "unauthorized"},
		"login token reused":   {"blue-sa-token", checkIn(good), http.StatusUnauthorized, "unauthorized"},
		"wrong protocol":       {session, mutate(func(c *protocol.CheckIn) { c.Protocol = "v9" }), http.StatusBadRequest, "unsupported protocol"},
		"forged fingerprint":   {session, mutate(func(c *protocol.CheckIn) { c.Keys[0].Fingerprint = other.Fingerprint }), http.StatusBadRequest, "does not match"},
		"active not reported":  {session, mutate(func(c *protocol.CheckIn) { c.Controller.ActiveFingerprint = other.Fingerprint }), http.StatusBadRequest, "active_fingerprint"},
		"unknown capability":   {session, mutate(func(c *protocol.CheckIn) { c.Capabilities = []string{"root"} }), http.StatusBadRequest, "unknown capability"},
		"bad namespace":        {session, mutate(func(c *protocol.CheckIn) { c.Controller.Namespace = "Bad_NS" }), http.StatusBadRequest, "namespace"},
		"bad order priority":   {session, mutate(func(c *protocol.CheckIn) { c.Controller.KeyOrderPriority = "Random" }), http.StatusBadRequest, "key_order_priority"},
		"no keys":              {session, mutate(func(c *protocol.CheckIn) { c.Keys = nil }), http.StatusBadRequest, "keys must not be empty"},
		"duplicate key":        {session, mutate(func(c *protocol.CheckIn) { c.Keys = append(c.Keys, good) }), http.StatusBadRequest, "duplicate key"},
		"garbage certificate":  {session, mutate(func(c *protocol.CheckIn) { c.Keys[0].Certificate = "nope" }), http.StatusBadRequest, "certificate"},
		"unknown field":        {session, `{"protocol":"v1","surprise":1}`, http.StatusBadRequest, "invalid request body"},
		"wrong content type":   {session, nil, http.StatusUnsupportedMediaType, "content type"},
		"oversized check-in":   {session, `{"agent_version":"` + strings.Repeat("a", maxCheckInBody) + `"}`, http.StatusRequestEntityTooLarge, "too large"},
		"session of other env": {otherEnvSession(t), checkIn(good), http.StatusUnauthorized, "unauthorized"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if name == "wrong content type" {
				req := httptest.NewRequest(http.MethodPost, "/agent/v1/checkin", strings.NewReader("{}"))
				req.Header.Set("Authorization", "Bearer "+tc.auth)
				req.Header.Set("Content-Type", "text/plain")
				rec = httptest.NewRecorder()
				h.h.ServeHTTP(rec, req)
			} else {
				rec = h.do(http.MethodPost, "/agent/v1/checkin", tc.auth, tc.body)
			}
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.msg) {
				t.Fatalf("status = %d %s, want %d containing %q", rec.Code, rec.Body, tc.want, tc.msg)
			}
		})
	}
	if states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"}); len(states) != 0 {
		t.Errorf("a rejected check-in was stored: %+v", states)
	}
}

func otherEnvSession(t *testing.T) string {
	t.Helper()
	s, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := s.Issue("use1-blue")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestAdminFleet(t *testing.T) {
	if rec := newHarness(t, "").do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("admin API without a configured token = %d, want 404", rec.Code)
	}

	h := newHarness(t, adminToken)
	for _, auth := range []string{"", "wrong", adminToken + "x"} {
		if rec := h.do(http.MethodGet, "/api/v1/admin/fleet", auth, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("auth %q = %d, want 401", auth, rec.Code)
		}
	}

	session := h.login()
	key := protoKey(t, time.Now().Add(-time.Hour))
	if rec := h.do(http.MethodPost, "/agent/v1/checkin", session, checkIn(key)); rec.Code != http.StatusOK {
		t.Fatalf("check-in = %d", rec.Code)
	}
	rec := h.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet = %d %s", rec.Code, rec.Body)
	}
	var f fleet.Fleet
	if err := json.NewDecoder(rec.Body).Decode(&f); err != nil {
		t.Fatal(err)
	}
	if f.Env != "dev" || len(f.Agents) != 2 {
		t.Fatalf("fleet = %+v", f)
	}
	// use2-blue never checked in, so it is out of scope and blue's key is the env key
	if f.EnvKey == nil || f.EnvKey.Fingerprint != key.Fingerprint {
		t.Errorf("env key = %+v", f.EnvKey)
	}
	if !f.Agents[0].Healthy || f.Agents[1].CheckedIn {
		t.Errorf("agents = %+v", f.Agents)
	}
}

var _ LoginVerifier = fakeVerifier{}

func TestSession_RoutesByMethod(t *testing.T) {
	h := newHarness(t, "")
	rec := h.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{
		Method: protocol.MethodAWSSTS,
		AWS:    &protocol.SignedRequest{URL: "https://sts.us-east-2.amazonaws.com/", Body: "signed-by-use2"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"agent_id":"use2-blue"`) {
		t.Fatalf("aws login = %d %s", rec.Code, rec.Body)
	}
	// a k8s token sent under the aws method goes to the aws verifier, which rejects it
	rec = h.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodAWSSTS, Token: "blue-sa-token"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cross-method login = %d", rec.Code)
	}
}

func TestUserRoutes(t *testing.T) {
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: "system:serviceaccount:a:agent"}}}
`), "")
	if err != nil {
		t.Fatal(err)
	}
	agentSessions, _ := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "http://localhost:4100", "dev", nil)
	userSessions, err := userauth.NewSessions([]byte("fedcba9876543210fedcba9876543210"), "http://localhost:4100", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	users := userauth.NewHandler(userauth.HandlerOptions{
		Sessions: userSessions, PublicURL: "http://localhost:4100", Org: "example-org",
		Envs: []userauth.EnvPolicy{{Name: "dev"}}, Logger: slog.New(slog.DiscardHandler),
	})
	ui := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>ui</html>")) })
	h := NewHost(HostOptions{
		Users: users, WebUI: ui, HSTS: true,
		Envs: []*Server{New(Options{
			Env: "dev", Registry: reg, Sessions: agentSessions, Store: store.NewMemory(),
			Users: users.Env("dev"), HSTS: true, Logger: slog.New(slog.DiscardHandler),
		})},
	})

	get := func(path, session string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if session != "" {
			req.AddCookie(&http.Cookie{Name: "sealer_session", Value: session})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/api/v1/fleet", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fleet without a session = %d", rec.Code)
	}
	agentSession, _, _ := agentSessions.Issue("use1-blue")
	if rec := get("/api/v1/fleet", agentSession); rec.Code != http.StatusUnauthorized {
		t.Fatalf("fleet with an agent session as cookie = %d", rec.Code)
	}
	// the fleet is for admins
	session, _, _ := userSessions.Issue(userauth.User{ID: 1004, Login: "dave"}, userauth.Grants{"dev": false})
	if rec := get("/api/v1/fleet", session); rec.Code != http.StatusForbidden {
		t.Fatalf("fleet for a user who is not an admin = %d", rec.Code)
	}
	admin, _, _ := userSessions.Issue(userauth.User{ID: 1001, Login: "alice"}, userauth.Grants{"dev": true})
	rec := get("/api/v1/fleet", admin)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"use1-blue"`) {
		t.Fatalf("fleet = %d %s", rec.Code, rec.Body)
	}
	// the env's own path serves the same
	if rec := get("/api/v1/envs/dev/fleet", admin); rec.Code != http.StatusOK {
		t.Fatalf("fleet under the env's path = %d", rec.Code)
	}
	// everyone sees whether sealing works, without agent names
	rec = get("/api/v1/status", session)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"sealing":"unavailable"`) ||
		!strings.Contains(rec.Body.String(), `"total":1`) || strings.Contains(rec.Body.String(), "use1-blue") {
		t.Fatalf("status = %d %s", rec.Code, rec.Body)
	}
	if rec := get("/api/v1/status", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without a session = %d", rec.Code)
	}

	if rec := get("/api/v1/nope", session); rec.Code != http.StatusNotFound || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Fatalf("unknown api route = %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	rec = get("/agents/use1-blue", "")
	if rec.Body.String() != "<html>ui</html>" {
		t.Fatalf("ui route = %d %s", rec.Code, rec.Body)
	}
	for header, want := range map[string]string{
		"Content-Security-Policy":   "script-src 'self'",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=",
		"X-Content-Type-Options":    "nosniff",
	} {
		if got := rec.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}
}

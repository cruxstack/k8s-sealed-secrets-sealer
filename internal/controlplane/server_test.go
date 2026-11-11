package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
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

// agentSession issues a session to a registered agent, as a login would.
func agentSession(t *testing.T, sessions *agentauth.Sessions, reg *registry.Registry, id string) string {
	t.Helper()
	a, ok := reg.Agent(id)
	if !ok {
		t.Fatalf("no agent %q", id)
	}
	token, _, err := sessions.Issue(id, reg.Binding(a), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return token
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

// sourceVerifier records the source a login came from.
type sourceVerifier struct{ seen *string }

func (v sourceVerifier) VerifyLogin(ctx context.Context, _ protocol.SessionRequest) (*registry.Agent, error) {
	*v.seen = agentauth.SourceFrom(ctx)
	return nil, agentauth.ErrUnauthorized
}

// The STS call limit counts per source, so logins carry their address.
func TestSession_PassesItsSourceToTheVerifier(t *testing.T) {
	sessions, _ := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", nil)
	var seen string
	srv := New(Options{
		Env: "dev", Registry: &registry.Registry{}, Sessions: sessions, Store: store.NewMemory(),
		Logins: map[string]LoginVerifier{protocol.MethodAWSSTS: sourceVerifier{seen: &seen}},
		Logger: slog.New(slog.DiscardHandler),
	})
	req := httptest.NewRequest(http.MethodPost, "/agent/v1/session", strings.NewReader(`{"method":"aws-sts","aws":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:40000"
	srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if seen != "198.51.100.7" {
		t.Fatalf("source = %q", seen)
	}
}

// An agent renews its session with the session itself, before it expires,
// so it needs its identity (and, for aws-sts, a call to STS) only when it
// starts or its session lapsed.
func TestSession_Renews(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent+use2Agent))
	session, _ := rh.login("use1-blue")
	rh.advance(10 * time.Minute)
	renewed, code := rh.renew(session)
	if code != http.StatusOK || renewed == "" || renewed == session {
		t.Fatalf("renew = %d %q", code, renewed)
	}
	if !strings.Contains(rh.logs.String(), "event=agent.session_renewed") {
		t.Errorf("the renewal was not logged:\n%s", rh.logs)
	}
	// the renewed session lasts its own 15 minutes
	rh.advance(10 * time.Minute)
	if code := rh.checkIn(renewed); code != http.StatusOK {
		t.Fatalf("check-in with the renewed session = %d", code)
	}
	if code := rh.checkIn(session); code != http.StatusUnauthorized {
		t.Fatalf("check-in with the old session, expired = %d", code)
	}

	// a session that lapsed, none at all, or one of another env cannot be
	// renewed; neither can a removed agent's
	if _, code := rh.renew(session); code != http.StatusUnauthorized {
		t.Fatalf("renewing an expired session = %d", code)
	}
	if _, code := rh.renew(""); code != http.StatusUnauthorized {
		t.Fatalf("renewing without a session = %d", code)
	}
	if _, code := rh.renew(otherEnvSession(t)); code != http.StatusUnauthorized {
		t.Fatalf("renewing another env's session = %d", code)
	}
	other, _ := rh.login("use2-blue")
	rh.next = parseRegistry(t, use1Agent)
	rh.advance(RegistryReloadInterval)
	rh.checkIn(renewed)
	rh.settle()
	if _, code := rh.renew(other); code != http.StatusUnauthorized {
		t.Fatalf("renewing a removed agent's session = %d", code)
	}
}

// Renewal carries the time the agent last logged in with its identity: a
// session taken from an agent cannot be renewed for ever, and the agent
// proves its identity again once that is agentauth.RenewalLimit old.
func TestSession_RenewsForALimitedTimeAfterALogin(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent))
	session, _ := rh.login("use1-blue")
	loggedIn := rh.now()
	// renewed a minute before each session ends, as agents do
	renewals := 0
	for rh.now().Add(agentauth.SessionTTL).Sub(loggedIn) < agentauth.RenewalLimit {
		rh.advance(agentauth.SessionTTL - time.Minute)
		renewed, code := rh.renew(session)
		if code != http.StatusOK {
			t.Fatalf("renewal %d, %s after the login = %d", renewals, rh.now().Sub(loggedIn), code)
		}
		session = renewed
		renewals++
	}
	rh.advance(agentauth.SessionTTL - time.Minute)
	if _, code := rh.renew(session); code != http.StatusUnauthorized {
		t.Fatalf("renewal %s after the login = %d, want 401", rh.now().Sub(loggedIn), code)
	}
	// the session itself still works until it ends, and a login starts
	// afresh
	if code := rh.checkIn(session); code != http.StatusOK {
		t.Fatalf("check-in with the last session = %d", code)
	}
	fresh, code := rh.login("use1-blue")
	if code != http.StatusOK {
		t.Fatalf("login = %d", code)
	}
	rh.advance(agentauth.SessionTTL - time.Minute)
	if _, code := rh.renew(fresh); code != http.StatusOK {
		t.Fatalf("renewing the new login's session = %d", code)
	}
	if renewals < 40 {
		t.Fatalf("only %d renewals before the limit", renewals)
	}
}

// Sessions issued before they carried the agent's binding are refused, so
// agents log in again once after the upgrade.
func TestSession_RefusesSessionsWithoutABinding(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent))
	legacy, _, err := rh.srv.sessions.Issue("use1-blue", "", rh.now())
	if err != nil {
		t.Fatal(err)
	}
	if code := rh.checkIn(legacy); code != http.StatusUnauthorized {
		t.Fatalf("check-in = %d, want 401", code)
	}
	if _, code := rh.renew(legacy); code != http.StatusUnauthorized {
		t.Fatalf("renew = %d, want 401", code)
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

// Agents report their check-in interval in a header, so the control plane
// counts each healthy for three of its own intervals.
func TestCheckIn_RecordsTheAgentsInterval(t *testing.T) {
	cases := map[string]struct {
		header       string
		stored, next int
	}{
		"reported":                {header: "60", stored: 60, next: 60},
		"none, as older agents":   {header: "", stored: 0, next: 15},
		"below an agent's bounds": {header: "1", stored: 5, next: 5},
		"above an agent's bounds": {header: "86400", stored: 300, next: 300},
		"not whole seconds":       {header: "1m", stored: 0, next: 15},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "")
			session := h.login()
			body, _ := json.Marshal(checkIn(protoKey(t, time.Now().Add(-time.Hour))))
			req := httptest.NewRequest(http.MethodPost, "/agent/v1/checkin", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+session)
			if tc.header != "" {
				req.Header.Set(protocol.CheckInIntervalHeader, tc.header)
			}
			rec := httptest.NewRecorder()
			h.h.ServeHTTP(rec, req)
			var resp protocol.CheckInResponse
			if rec.Code != http.StatusOK || json.NewDecoder(rec.Body).Decode(&resp) != nil {
				t.Fatalf("check-in = %d %s", rec.Code, rec.Body)
			}
			states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"})
			if got := states["use1-blue"].CheckInIntervalSeconds; got != tc.stored || resp.NextCheckInSeconds != tc.next {
				t.Fatalf("stored %d, next %d; want %d, %d", got, resp.NextCheckInSeconds, tc.stored, tc.next)
			}
		})
	}
}

// An agent newer than the control plane may send fields it does not know
// and list the protocol versions it speaks; older agents send only one.
func TestAgentAPI_AcceptsNewerAgents(t *testing.T) {
	h := newHarness(t, "")
	if rec := h.do(http.MethodPost, "/agent/v1/session", "", `{"method":"k8s-oidc","token":"blue-sa-token","future_field":true}`); rec.Code != http.StatusOK {
		t.Fatalf("login with an unknown field = %d %s", rec.Code, rec.Body)
	}
	session := h.login()

	in := checkIn(protoKey(t, time.Now().Add(-time.Hour)))
	in.Protocol, in.Protocols = "", []string{"v2", protocol.Version}
	var body map[string]any
	b, _ := json.Marshal(in)
	if err := json.Unmarshal(b, &body); err != nil {
		t.Fatal(err)
	}
	body["future_field"] = 30
	body["controller"].(map[string]any)["future_field"] = "x"
	if rec := h.do(http.MethodPost, "/agent/v1/checkin", session, body); rec.Code != http.StatusOK {
		t.Fatalf("check-in with unknown fields = %d %s", rec.Code, rec.Body)
	}
	states, _ := h.store.GetAgentStates(context.Background(), []string{"use1-blue"})
	if got := states["use1-blue"].Protocol; got != protocol.Version {
		t.Fatalf("protocol = %q, want %q", got, protocol.Version)
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
		"no known protocol":    {session, mutate(func(c *protocol.CheckIn) { c.Protocol, c.Protocols = "", []string{"v8", "v9"} }), http.StatusBadRequest, "unsupported protocol"},
		"too many protocols":   {session, mutate(func(c *protocol.CheckIn) { c.Protocols = slices.Repeat([]string{"v1"}, protocol.MaxProtocols+1) }), http.StatusBadRequest, "too many protocols"},
		"not JSON":             {session, `{"protocol":"v1",`, http.StatusBadRequest, "invalid request body"},
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
	token, _, err := s.Issue("use1-blue", "", time.Now())
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
	agentSession, _, _ := agentSessions.Issue("use1-blue", "", time.Now())
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

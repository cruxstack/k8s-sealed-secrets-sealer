package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/agentauth"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/fleet"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/protocol"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/registry"
	"github.com/cruxstack/k8s-sealed-secrets-sealer/internal/store"
)

// reloadHarness serves an env whose registry can be changed under it.
type reloadHarness struct {
	t     *testing.T
	srv   *Server
	h     http.Handler
	logs  *bytes.Buffer
	clock time.Time

	mu      sync.Mutex
	next    *registry.Registry
	failure error
	reads   int
	// block, when set, holds each read until it is closed
	block chan struct{}
	// during runs in each read, before it returns
	during func()
}

func parseRegistry(t *testing.T, agents string) *registry.Registry {
	t.Helper()
	reg, err := registry.Parse([]byte(`
issuers: [{name: local, url: "https://k8s.example.com", jwksFile: k.json}]
agents:
`+agents), "")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// loginsFor accepts "<agent id>-token" for each agent in reg.
func loginsFor(reg *registry.Registry) map[string]LoginVerifier {
	tokens := map[string]string{}
	for _, a := range reg.Agents {
		tokens[a.ID+"-token"] = a.ID
	}
	return map[string]LoginVerifier{protocol.MethodK8sOIDC: fakeVerifier{reg: reg, tokens: tokens}}
}

func newReloadHarness(t *testing.T, reg *registry.Registry) *reloadHarness {
	t.Helper()
	rh := &reloadHarness{t: t, logs: &bytes.Buffer{}, clock: time.Now()}
	sessions, err := agentauth.NewSessions([]byte("0123456789abcdef0123456789abcdef"), "https://sealer.dev.example.com", "dev", rh.now)
	if err != nil {
		t.Fatal(err)
	}
	srv := New(Options{
		Logger:   slog.New(slog.NewTextHandler(rh.logs, nil)),
		Env:      "dev",
		Registry: reg,
		Logins:   loginsFor(reg),
		ReloadRegistry: func(context.Context) (*registry.Registry, map[string]LoginVerifier, error) {
			rh.mu.Lock()
			block, during := rh.block, rh.during
			rh.mu.Unlock()
			if block != nil {
				<-block
			}
			if during != nil {
				during()
			}
			rh.mu.Lock()
			defer rh.mu.Unlock()
			rh.reads++
			if rh.failure != nil {
				return nil, nil, rh.failure
			}
			next := rh.next
			rh.next = nil
			if next == nil {
				return nil, nil, nil
			}
			return next, loginsFor(next), nil
		},
		Sessions:   sessions,
		Store:      store.NewMemory(),
		AdminToken: adminToken,
		Now:        rh.now,
	})
	rh.srv, rh.h = srv, srv.Handler()
	return rh
}

func (rh *reloadHarness) now() time.Time {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.clock
}

func (rh *reloadHarness) advance(d time.Duration) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	rh.clock = rh.clock.Add(d)
}

// settle waits for a read of the registry that a request started.
func (rh *reloadHarness) settle() { rh.srv.reloading.Wait() }

func (rh *reloadHarness) do(method, path, auth string, body any) *httptest.ResponseRecorder {
	rh.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			rh.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	rh.h.ServeHTTP(rec, req)
	return rec
}

func (rh *reloadHarness) login(id string) (string, int) {
	rec := rh.do(http.MethodPost, "/agent/v1/session", "", protocol.SessionRequest{Method: protocol.MethodK8sOIDC, Token: id + "-token"})
	var resp protocol.SessionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	return resp.Token, rec.Code
}

// renew renews a session with itself, as agents do before it expires.
func (rh *reloadHarness) renew(session string) (string, int) {
	rec := rh.do(http.MethodPost, "/agent/v1/session", session, protocol.SessionRequest{Method: protocol.MethodRenew})
	var resp protocol.SessionResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	return resp.Token, rec.Code
}

func (rh *reloadHarness) checkIn(session string) int {
	rh.t.Helper()
	return rh.do(http.MethodPost, "/agent/v1/checkin", session, checkIn(protoKey(rh.t, rh.now().Add(-time.Hour)))).Code
}

func (rh *reloadHarness) fleetIDs() []string {
	rh.t.Helper()
	rec := rh.do(http.MethodGet, "/api/v1/admin/fleet", adminToken, nil)
	var f fleet.Fleet
	if err := json.NewDecoder(rec.Body).Decode(&f); err != nil {
		rh.t.Fatalf("fleet = %d %s", rec.Code, rec.Body)
	}
	var ids []string
	for _, a := range f.Agents {
		ids = append(ids, a.ID)
	}
	return ids
}

func (rh *reloadHarness) readCount() int {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.reads
}

const (
	use1Agent = "  - {id: use1-blue, cluster: blue, region: use1, capabilities: [seal], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:a:agent\"}}}\n"
	use2Agent = "  - {id: use2-blue, cluster: blue, region: use2, capabilities: [seal], identity: {k8s: {issuer: local, subject: \"system:serviceaccount:b:agent\"}}}\n"
)

// An agent removed from the registry loses access when the registry is
// next read, without a restart; a registry that cannot be read leaves the
// one in force.
func TestRegistryReload(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent+use2Agent))
	session, code := rh.login("use1-blue")
	if code != http.StatusOK || rh.checkIn(session) != http.StatusOK {
		t.Fatalf("login = %d", code)
	}

	// use1-blue is removed; nothing is read before a minute has passed
	rh.next = parseRegistry(t, use2Agent)
	rh.settle()
	if rh.checkIn(session) != http.StatusOK || rh.readCount() != 0 {
		t.Fatalf("the registry was read %d times within a minute", rh.readCount())
	}

	// a read that fails keeps the registry in force, and is not retried on
	// every request
	rh.mu.Lock()
	rh.failure = errors.New("parameter not found")
	rh.mu.Unlock()
	rh.advance(RegistryReloadInterval)
	for range 3 {
		if code := rh.checkIn(session); code != http.StatusOK {
			t.Fatalf("check-in after a failed read = %d", code)
		}
		rh.settle()
	}
	if n := rh.readCount(); n != 1 || !strings.Contains(rh.logs.String(), "event=registry.reload_failed") {
		t.Fatalf("reads = %d, logs:\n%s", n, rh.logs)
	}

	// the next read takes effect for sessions, logins and the fleet alike,
	// once it is done
	rh.mu.Lock()
	rh.failure = nil
	rh.mu.Unlock()
	rh.advance(RegistryReloadInterval)
	rh.checkIn(session)
	rh.settle()
	if code := rh.checkIn(session); code != http.StatusUnauthorized {
		t.Fatalf("check-in by a removed agent = %d, want 401", code)
	}
	if !strings.Contains(rh.logs.String(), "event=registry.reloaded") {
		t.Fatalf("logs:\n%s", rh.logs)
	}
	if _, code := rh.login("use1-blue"); code != http.StatusUnauthorized {
		t.Fatalf("login by a removed agent = %d, want 401", code)
	}
	if ids := rh.fleetIDs(); strings.Join(ids, ",") != "use2-blue" {
		t.Fatalf("fleet = %v", ids)
	}

	// an unchanged registry keeps the one in force
	rh.advance(RegistryReloadInterval)
	if _, code := rh.login("use2-blue"); code != http.StatusOK {
		t.Fatalf("login after an unchanged read = %d", code)
	}
	if rh.settle(); rh.readCount() != 3 {
		t.Fatalf("reads = %d", rh.readCount())
	}
}

// Reading the registry takes none of a request's time: a slow read leaves
// requests to the registry in force meanwhile, and a request arriving then
// starts no other read.
func TestRegistryReload_RunsBesideRequests(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent+use2Agent))
	session, _ := rh.login("use1-blue")
	release := make(chan struct{})
	rh.mu.Lock()
	rh.block = release
	rh.next = parseRegistry(t, use2Agent)
	rh.mu.Unlock()
	rh.advance(RegistryReloadInterval)

	done := make(chan int, 4)
	for range 3 {
		go func() { done <- rh.checkIn(session) }()
	}
	go func() { done <- rh.do(http.MethodGet, "/agent/v1/commands?wait=1", session, nil).Code }()
	for range 4 {
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Fatalf("request during the read = %d", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a request waited for the registry to be read")
		}
	}
	close(release)
	rh.settle()
	if n := rh.readCount(); n != 1 {
		t.Fatalf("reads = %d, want 1", n)
	}
	if code := rh.checkIn(session); code != http.StatusUnauthorized {
		t.Fatalf("check-in by a removed agent after the read = %d, want 401", code)
	}
}

// On Lambda, an instance can be frozen in the middle of a read and thawed
// long after its time ran out: that is not a failure of the registry, and
// the next request reads it again.
func TestRegistryReload_ReadsAgainAfterAFreeze(t *testing.T) {
	rh := newReloadHarness(t, parseRegistry(t, use1Agent+use2Agent))
	session, _ := rh.login("use1-blue")
	rh.mu.Lock()
	rh.failure = context.DeadlineExceeded
	rh.during = func() { rh.advance(time.Hour) }
	rh.mu.Unlock()
	rh.advance(RegistryReloadInterval)
	rh.checkIn(session)
	rh.settle()
	if strings.Contains(rh.logs.String(), "event=registry.reload_failed") {
		t.Fatalf("an interrupted read was logged as failed:\n%s", rh.logs)
	}

	rh.mu.Lock()
	rh.failure, rh.during = nil, nil
	rh.next = parseRegistry(t, use2Agent)
	rh.mu.Unlock()
	rh.checkIn(session)
	rh.settle()
	if n := rh.readCount(); n != 2 {
		t.Fatalf("reads = %d, want the registry read again at once", n)
	}
	if code := rh.checkIn(session); code != http.StatusUnauthorized {
		t.Fatalf("check-in by a removed agent = %d, want 401", code)
	}
}

// A session is bound to its agent as the registry had it: a registry change
// that gives the agent's ID another identity or other capabilities ends its
// sessions, and renewing one does not get around that.
func TestRegistryReload_EndsSessionsOfAReboundAgent(t *testing.T) {
	cases := map[string]string{
		"another service account": strings.Replace(use1Agent, "a:agent", "c:agent", 1),
		"more capabilities":       strings.Replace(use1Agent, "[seal]", "[seal, keys]", 1),
	}
	for name, rebound := range cases {
		t.Run(name, func(t *testing.T) {
			rh := newReloadHarness(t, parseRegistry(t, use1Agent+use2Agent))
			session, _ := rh.login("use1-blue")
			other, _ := rh.login("use2-blue")
			rh.next = parseRegistry(t, rebound+use2Agent)
			rh.advance(RegistryReloadInterval)
			rh.checkIn(other)
			rh.settle()
			if code := rh.checkIn(session); code != http.StatusUnauthorized {
				t.Fatalf("check-in with a session of the agent as it was = %d, want 401", code)
			}
			if _, code := rh.renew(session); code != http.StatusUnauthorized {
				t.Fatalf("renewing it = %d, want 401", code)
			}
			// the agent untouched keeps its session
			if code := rh.checkIn(other); code != http.StatusOK {
				t.Fatalf("check-in by the other agent = %d", code)
			}
			// as registered now, it logs in again
			fresh, code := rh.login("use1-blue")
			if code != http.StatusOK || rh.checkIn(fresh) != http.StatusOK {
				t.Fatalf("login as registered now = %d", code)
			}
		})
	}
}
